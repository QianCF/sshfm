/*
 * sshfm - an SSH file manager with a simple text editor.
 *
 * Any username/password is accepted.  After login the client gets a TUI that
 * manages a real directory tree ("sandbox root", -dir, default ./data).
 *
 * On-disk layout inside the sandbox:
 *   1<name>   the real file or directory
 *   0<name>   a sidecar *file* holding metadata for <name>:
 *                 creator_ip=..., creator_ts=..., editor_ip=..., mtime_ts=...
 *
 * Layout: the bottom three lines are always reserved
 *   - bottom-2 .. : key bar (wraps, eats into the main area)
 *   - rows-1      : message line
 *   - rows        : input line
 * Everything above is the main content (directory list or editor), which
 * wraps and scrolls.  All bars span the full terminal width.
 *
 * Build: ./build.sh   Run: ./sshfm [rootdir] [port]
 */
#include <libssh/libssh.h>
#include <libssh/server.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cerrno>
#include <ctime>
#include <clocale>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <mutex>
#include <thread>
#include <atomic>
#include <algorithm>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>

/* ------------------------------------------------------------------ */
/* broadcast: any filesystem change bumps a global version             */
/* ------------------------------------------------------------------ */

/* is the TCP connection still ESTABLISHED?  A peer that vanished leaves the
 * socket in CLOSE_WAIT / FIN_WAIT / ... while libssh may still block, so we
 * check the kernel state directly and drop such sessions. */
static bool sock_alive(int fd)
{
	if (fd < 0)
		return false;
	struct tcp_info ti;
	socklen_t len = sizeof(ti);
	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0)
		return false;
	return ti.tcpi_state == TCP_ESTABLISHED;
}

/* number of currently connected sessions (shown in the title bar) */
static std::atomic<int> g_online{0};
/* bumped on every connect/disconnect so other sessions redraw the title */
static std::atomic<unsigned long long> g_online_epoch{0};
struct OnlineGuard {
	OnlineGuard() { g_online++; g_online_epoch++; }
	~OnlineGuard() { g_online--; g_online_epoch++; }
};

/* live directory of every session, for the "<here>" online count */
static std::mutex g_sess_mtx;
static std::map<unsigned long long, std::string> g_sessions;
static std::atomic<unsigned long long> g_next_sid{0};

/* ---- BEL broadcasts ---- */
struct BellEvent {
	unsigned long long id;
	time_t ts;
	int type;              /* 0 = to one directory, 1 = to everyone */
	std::string dir;
};
static std::mutex g_bell_mtx;
static std::list<BellEvent> g_bells;
static std::atomic<unsigned long long> g_bell_seq{0};
static void push_bell(int type, const std::string &dir)
{
	{
		std::lock_guard<std::mutex> lk(g_bell_mtx);
		time_t now = time(nullptr);
		while (!g_bells.empty() && g_bells.front().ts < now - 60)
			g_bells.pop_front();                /* drop stale (O(1) each) */
		g_bells.push_back({++g_bell_seq, now, type, dir});
	}
}
/* ---- broadcast messages (Shift+B) ---- */
struct BcastEvent {
	unsigned long long id;
	time_t ts;
	std::string from;
	std::string text;
};
static std::mutex g_msg_mtx;
static std::list<BcastEvent> g_msgs;
static std::atomic<unsigned long long> g_msg_seq{0};
static void push_message(const std::string &from, const std::string &text)
{
	{
		std::lock_guard<std::mutex> lk(g_msg_mtx);
		time_t now = time(nullptr);
		while (!g_msgs.empty() && g_msgs.front().ts < now - 60)
			g_msgs.pop_front();                 /* drop stale (O(1) each) */
		g_msgs.push_back({++g_msg_seq, now, from, text});
	}
}

static std::mutex g_ver_mtx;
static unsigned long long g_version = 0;

static void bump_version()
{
	std::lock_guard<std::mutex> lk(g_ver_mtx);
	g_version++;
}
static unsigned long long get_version()
{
	std::lock_guard<std::mutex> lk(g_ver_mtx);
	return g_version;
}

/* A file being edited by one session cannot be opened by another. */
static std::mutex g_lock_mtx;
static std::set<std::string> g_filelocks;
/* bumped whenever a lock is taken or released, so every session can
 * repaint the reverse-video state of locked names */
static std::atomic<unsigned long long> g_lock_epoch{0};

static bool filelock_acquire(const std::string &rel)
{
	std::lock_guard<std::mutex> lk(g_lock_mtx);
	if (g_filelocks.count(rel))
		return false;
	g_filelocks.insert(rel);
	g_lock_epoch++;
	return true;
}
static void filelock_release(const std::string &rel)
{
	std::lock_guard<std::mutex> lk(g_lock_mtx);
	if (g_filelocks.erase(rel))
		g_lock_epoch++;
}
static bool filelock_held(const std::string &rel)
{
	std::lock_guard<std::mutex> lk(g_lock_mtx);
	return g_filelocks.count(rel) > 0;
}

/* ---- global path events (rename / delete of folders & files) ---- */
struct PathEvent {
	unsigned long long id;
	time_t ts;
	int type;                 /* 0 = moved (a -> b), 1 = deleted (a) */
	std::string a, b;
};
static std::mutex g_ev_mtx;
static std::list<PathEvent> g_events;
static std::atomic<unsigned long long> g_ev_seq{0};   /* last assigned id */
static void push_event(int type, const std::string &a, const std::string &b = "")
{
	{
		std::lock_guard<std::mutex> lk(g_ev_mtx);
		time_t now = time(nullptr);
		while (!g_events.empty() && g_events.front().ts < now - 60)
			g_events.pop_front();               /* drop stale (O(1) each) */
		g_events.push_back({++g_ev_seq, now, type, a, b});
	}
	bump_version();
}

/* ------------------------------------------------------------------ */
/* UTF-8 helpers                                                       */
/* ------------------------------------------------------------------ */

static int u8seqlen(unsigned char c)
{
	if (c < 0x80) return 1;
	if ((c & 0xE0) == 0xC0) return 2;
	if ((c & 0xF0) == 0xE0) return 3;
	if ((c & 0xF8) == 0xF0) return 4;
	return 1;
}

/* East-Asian-wide / emoji-presentation code point ranges (width 2) */
static const std::pair<unsigned, unsigned> WIDE_EXTRA[] = {
	{0x231A, 0x231B}, {0x23E9, 0x23EC}, {0x23F0, 0x23F0}, {0x23F3, 0x23F3},
	{0x25FD, 0x25FE}, {0x2614, 0x2615}, {0x2648, 0x2653}, {0x267F, 0x267F},
	{0x2693, 0x2693}, {0x26A1, 0x26A1}, {0x26AA, 0x26AB}, {0x26BD, 0x26BE},
	{0x26C4, 0x26C5}, {0x26CE, 0x26CE}, {0x26D4, 0x26D4}, {0x26EA, 0x26EA},
	{0x26F2, 0x26F3}, {0x26F5, 0x26F5}, {0x26FA, 0x26FA}, {0x26FD, 0x26FD},
	{0x2705, 0x2705}, {0x270A, 0x270B}, {0x2728, 0x2728}, {0x274C, 0x274C},
	{0x274E, 0x274E}, {0x2753, 0x2755}, {0x2757, 0x2757}, {0x2795, 0x2797},
	{0x27B0, 0x27B0}, {0x27BF, 0x27BF}, {0x2B1B, 0x2B1C}, {0x2B50, 0x2B50},
	{0x2B55, 0x2B55},
	{0x1F004, 0x1F004}, {0x1F0CF, 0x1F0CF}, {0x1F18E, 0x1F18E},
	{0x1F191, 0x1F19A}, {0x1F1E6, 0x1F1FF}, {0x1F200, 0x1F202}, {0x1F210, 0x1F23B},
	{0x1F240, 0x1F248}, {0x1F250, 0x1F251}, {0x1F300, 0x1F320},
	{0x1F32D, 0x1F335}, {0x1F337, 0x1F37C}, {0x1F37E, 0x1F393},
	{0x1F3A0, 0x1F3CA}, {0x1F3CF, 0x1F3D3}, {0x1F3E0, 0x1F3F0},
	{0x1F3F4, 0x1F3F4}, {0x1F3F8, 0x1F43E}, {0x1F440, 0x1F440},
	{0x1F442, 0x1F4FC}, {0x1F4FF, 0x1F53D}, {0x1F54B, 0x1F54E},
	{0x1F550, 0x1F567}, {0x1F57A, 0x1F57A}, {0x1F595, 0x1F596},
	{0x1F5A4, 0x1F5A4}, {0x1F5FB, 0x1F64F}, {0x1F680, 0x1F6C5},
	{0x1F6CC, 0x1F6CC}, {0x1F6D0, 0x1F6D2}, {0x1F6D5, 0x1F6D7},
	{0x1F6EB, 0x1F6EC}, {0x1F6F4, 0x1F6FC}, {0x1F7E0, 0x1F7EB},
	{0x1F90C, 0x1F93A}, {0x1F93C, 0x1F945}, {0x1F947, 0x1F978},
	{0x1F97A, 0x1F9CB}, {0x1F9CD, 0x1F9FF}, {0x1FA70, 0x1FA74},
	{0x1FA78, 0x1FA7A}, {0x1FA80, 0x1FA86}, {0x1FA90, 0x1FAA8},
	{0x1FAB0, 0x1FAB6}, {0x1FAC0, 0x1FAC2}, {0x1FAD0, 0x1FAD6},
};

static int cpwidth(unsigned int c)
{
	if (c == 0) return 0;
	if (c < 32) return 0;
	if (c < 0x1100) return 1;
	if (c == 0x200B || c == 0x200C || c == 0x200D) return 0; /* ZWSP/ZWNJ/ZWJ */
	if (c >= 0xFE00 && c <= 0xFE0F) return 0;   /* variation selectors */
	if (c >= 0x1100 && c <= 0x115F) return 2;
	if (c >= 0x2E80 && c <= 0xA4CF) return 2;
	if (c >= 0xAC00 && c <= 0xD7A3) return 2;
	if (c >= 0xF900 && c <= 0xFAFF) return 2;
	if (c >= 0xFE30 && c <= 0xFE4F) return 2;
	if (c >= 0xFF00 && c <= 0xFF60) return 2;
	if (c >= 0xFFE0 && c <= 0xFFE6) return 2;
	if (c >= 0x20000 && c <= 0x3FFFD) return 2;
	for (const auto &r : WIDE_EXTRA)
		if (c >= r.first && c <= r.second)
			return 2;
	return 1;
}

static unsigned int u8decode(const std::string &s, size_t i, int *len)
{
	unsigned char c = (unsigned char)s[i];
	int n = u8seqlen(c);
	if (i + n > s.size()) { *len = 1; return c; }
	if (n == 1) { *len = 1; return c; }
	unsigned int v = (n == 2) ? (c & 0x1F) : (n == 3) ? (c & 0x0F) : (c & 0x07);
	for (int k = 1; k < n; k++) {
		unsigned char cc = (unsigned char)s[i + k];
		if ((cc & 0xC0) != 0x80) { *len = 1; return c; }
		v = (v << 6) | (cc & 0x3F);
	}
	*len = n;
	return v;
}

/* ---- grapheme clusters: the unit of width, movement and editing ---- */
static bool is_extend(unsigned int c)
{
	if (c >= 0xFE00 && c <= 0xFE0F) return true;   /* variation selectors */
	if (c >= 0x0300 && c <= 0x036F) return true;   /* combining diacritics */
	if (c >= 0x1AB0 && c <= 0x1AFF) return true;
	if (c >= 0x1DC0 && c <= 0x1DFF) return true;
	if (c >= 0x20D0 && c <= 0x20F0) return true;   /* incl. keycap 20E3 */
	if (c >= 0xFE20 && c <= 0xFE2F) return true;
	if (c >= 0xE0020 && c <= 0xE007F) return true; /* subdivision tags */
	if (c >= 0x1F3FB && c <= 0x1F3FF) return true; /* skin tone modifiers */
	if (c == 0x0E31 || (c >= 0x0E34 && c <= 0x0E3A)) return true;
	if (c >= 0x0E47 && c <= 0x0E4E) return true;
	if (c >= 0x200B && c <= 0x200F) return true;   /* zero-width / LRM..RLM */
	return false;
}
static bool is_ri(unsigned int c)
{
	return c >= 0x1F1E6 && c <= 0x1F1FF;           /* regional indicators */
}

/* byte index just past the cluster that starts at byte i */
static size_t next_cluster(const std::string &s, size_t i)
{
	size_t n = s.size();
	int nb;
	unsigned int c = u8decode(s, i, &nb);
	size_t j = i + (size_t)nb;
	if (c == 0x1B) {                 /* an ANSI escape sequence: zero width */
		if (j < n && (s[j] == '[' || s[j] == 'O')) {
			j++;
			while (j < n && !(s[j] >= '@' && s[j] <= '~'))
				j++;
			if (j < n)
				j++;             /* include the final byte */
		}
		return j;
	}
	if (is_ri(c) && j < n) {                       /* flag = pair of RIs */
		int nb2;
		unsigned int c2 = u8decode(s, j, &nb2);
		if (is_ri(c2))
			j += (size_t)nb2;
	}
	for (;;) {
		if (j >= n)
			break;
		int nb2;
		unsigned int c2 = u8decode(s, j, &nb2);
		if (c2 == 0x200D) {                        /* ZWJ joins the next char */
			j += (size_t)nb2;
			if (j < n) {
				int nb3;
				u8decode(s, j, &nb3);
				j += (size_t)nb3;
			}
			continue;
		}
		if (is_extend(c2)) {
			j += (size_t)nb2;
			continue;
		}
		break;
	}
	return j;
}

/* byte index where the cluster immediately before byte i starts */
static size_t prev_cluster(const std::string &s, size_t i)
{
	size_t p = 0, prev = 0;
	while (p < i) {
		prev = p;
		p = next_cluster(s, p);
	}
	return prev;
}

/* replace C0 control bytes (except TAB) and DEL with '?' so a hostile file
 * name or file content cannot inject terminal escape sequences.  The mapping
 * is 1 byte -> 1 byte, so byte offsets (editor cursors) stay valid. */
static std::string sanitize_ctrl(const std::string &s)
{
	std::string o = s;
	for (size_t i = 0; i < o.size(); i++) {
		unsigned char c = (unsigned char)o[i];
		if ((c < 0x20 && c != 0x09) || c == 0x7F)
			o[i] = '?';
	}
	return o;
}

/* display width of one cluster: 2 when emoji-presented, else max member.
 * The two knobs below are measured per client at login (see calibrate_client):
 * some terminals ignore VS16, some explode ZWJ chains into separate emoji. */
/* per-session (each session runs in its own thread): measured at login */
static thread_local int g_w_vs16 = 2;            /* VS16 emoji presentation */
static thread_local bool g_zwj_composed = true;  /* ZWJ chains composed? */

static int cluster_width(const std::string &s, size_t i, size_t end)
{
	{
		int nb0;
		if (u8decode(s, i, &nb0) == 0x1B)
			return 0;          /* escape sequences take no cells */
	}
	bool emoji = false, zwj = false;
	int w = 0;
	for (size_t k = i; k < end;) {
		int nb;
		unsigned int c = u8decode(s, k, &nb);
		if (c == 0xFE0F)
			emoji = true;                  /* emoji presentation forced */
		if (c == 0x200D)
			zwj = true;
		int cw = cpwidth(c);
		if (cw > w)
			w = cw;
		k += (size_t)nb;
	}
	if (emoji && g_w_vs16 == 2)
		return 2;
	if (zwj) {
		if (g_zwj_composed)
			return 2;
		/* the client explodes the chain: every visible member counts */
		int sum = 0;
		for (size_t k = i; k < end;) {
			int nb;
			unsigned int c = u8decode(s, k, &nb);
			if (c != 0x200D && !is_extend(c))
				sum += cpwidth(c);
			k += (size_t)nb;
		}
		return sum;
	}
	return w;
}

static int u8width(const std::string &s)
{
	int w = 0;
	for (size_t i = 0; i < s.size();) {
		size_t j = next_cluster(s, i);
		w += cluster_width(s, i, j);
		i = j;
	}
	return w;
}

static std::string u8clip(const std::string &s, int w)
{
	std::string out;
	int cw = 0;
	for (size_t i = 0; i < s.size();) {
		size_t j = next_cluster(s, i);
		int clw = cluster_width(s, i, j);
		if (cw + clw > w)
			break;
		out.append(s, i, j - i);
		cw += clw;
		i = j;
	}
	return out;
}

/* split into chunks of at most `w` display columns (cluster boundaries) */
static std::vector<std::string> u8wrap(const std::string &s, int w)
{
	std::vector<std::string> out;
	if (w < 1) w = 1;
	std::string cur;
	int cw = 0;
	for (size_t i = 0; i < s.size();) {
		size_t j = next_cluster(s, i);
		int clw = cluster_width(s, i, j);
		if (cw + clw > w && !cur.empty()) {
			out.push_back(cur);
			cur.clear();
			cw = 0;
		}
		cur.append(s, i, j - i);
		cw += clw;
		i = j;
	}
	out.push_back(cur);
	return out;
}

/* where does byte-offset `cx` land in the wrapped chunks of `s` (width w)?
 * mirrors u8wrap exactly so the cursor matches the rendered text. */
static void cursor_chunk(const std::string &s, int cx, int w, int &chunk, int &col)
{
	chunk = 0;
	col = 0;
	if (w < 1) w = 1;
	std::string cur;
	for (size_t i = 0; i < s.size() && (int)i < cx;) {
		size_t j = next_cluster(s, i);
		int clw = cluster_width(s, i, j);
		if (col + clw > w && !cur.empty()) { chunk++; cur.clear(); col = 0; }
		cur.append(s, i, j - i);
		col += clw;
		i = j;
	}
}

/* byte offset of the cursor when it sits at (chunk, column) of a wrapped
 * line — mirrors u8wrap/cursor_chunk exactly */
static size_t chunk_byte_offset(const std::string &s, int chunk_want, int col_want, int w)
{
	if (w < 1) w = 1;
	int chunk = 0, col = 0;
	std::string cur;
	size_t i = 0;
	while (i < s.size()) {
		size_t j = next_cluster(s, i);
		int clw = cluster_width(s, i, j);
		if (col + clw > w && !cur.empty()) { chunk++; cur.clear(); col = 0; }
		if (chunk > chunk_want)
			return i;   /* start of the next chunk = the wanted chunk's end
			             * (its reserved cursor column) */
		if (chunk == chunk_want && col + clw > col_want)
			return i;
		cur.append(s, i, j - i);
		col += clw;
		i = j;
	}
	return s.size();
}

/* ------------------------------------------------------------------ */
/* linguistic name order: an embedded Unicode collation table          */
/* (zh_CN glibc collation: pinyin for CJK, interleaved with Latin)      */
/* ------------------------------------------------------------------ */

#include "colltab.inc"

static const unsigned COLL_UNDEF = 0xFFFFFFFFu;

/* decode the fixed-width (3 bytes/code point) table once; rank per defined
 * code point.  Order: glibc zh_CN collation with han interleaved at their
 * pinyin initial letters (a 啊 按 b 波 ... z 中). */
static unsigned coll_rank(unsigned cp)
{
	static std::vector<unsigned> *tab = nullptr;
	if (!tab) {
		tab = new std::vector<unsigned>(0x110000, COLL_UNDEF);
		size_t n = colltab_bin_len / 3;
		for (size_t i = 0; i < n; i++) {
			unsigned c = (unsigned)colltab_bin[i * 3]
			           | ((unsigned)colltab_bin[i * 3 + 1] << 8)
			           | ((unsigned)colltab_bin[i * 3 + 2] << 16);
			(*tab)[c] = (unsigned)i;
		}
	}
	return cp <= 0x10FFFF ? (*tab)[cp] : COLL_UNDEF;
}

/* compare names code point by code point using the collation ranks;
 * undefined code points sort last; bytes break ties */
static int name_cmp(const std::string &a, const std::string &b)
{
	size_t i = 0, j = 0;
	while (i < a.size() && j < b.size()) {
		int na, nb;
		unsigned ca = u8decode(a, i, &na);
		unsigned cb = u8decode(b, j, &nb);
		unsigned ra = coll_rank(ca), rb = coll_rank(cb);
		if (ra != rb)
			return ra < rb ? -1 : 1;
		i += (size_t)na;
		j += (size_t)nb;
	}
	if (i < a.size()) return 1;
	if (j < b.size()) return -1;
	return a < b ? -1 : (b < a ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/* small utilities                                                     */
/* ------------------------------------------------------------------ */

static std::string sfmt(const char *fmt, ...)
{
	char buf[8192];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return std::string(buf);
}

/* file size: use the smallest unit whose text fits the cell width */
static std::string fmt_size(long long n, int w)
{
	char buf[64];
	snprintf(buf, sizeof buf, "%lld", n);
	if ((int)strlen(buf) <= w)
		return std::string(buf);
	double v = (double)n;
	static const char *u = "KMGT";
	for (int i = 0; i < 4; i++) {
		v /= 1024.0;
		snprintf(buf, sizeof buf, "%.0f%c", v, u[i]);
		if ((int)strlen(buf) <= w)
			return std::string(buf);
	}
	return std::string(buf);
}


/* long unique id for every file/folder: time + counter + random */
static std::string new_id()
{
	static unsigned long long ctr = 0;
	srand((unsigned)(time(nullptr) ^ (getpid() << 16)) + (unsigned)++ctr);
	unsigned long long a = ((unsigned long long)rand() << 48)
	                     ^ ((unsigned long long)rand() << 32)
	                     ^ ((unsigned long long)rand() << 16)
	                     ^  (unsigned long long)rand();
	unsigned long long b = (unsigned long long)time(nullptr) * 1000003ULL
	                     + ++ctr * 0x9e3779b97f4a7c15ULL;
	return sfmt("%llx%llx", b, a);
}

static bool read_file(const std::string &path, std::string &out)
{
	int fd = open(path.c_str(), O_RDONLY);
	if (fd < 0) return false;
	char buf[8192];
	ssize_t n;
	out.clear();
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		out.append(buf, (size_t)n);
	close(fd);
	return true;
}

static bool write_file(const std::string &path, const std::string &data)
{
	int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) return false;
	size_t off = 0;
	while (off < data.size()) {
		ssize_t n = write(fd, data.data() + off, data.size() - off);
		if (n <= 0) { close(fd); return false; }
		off += (size_t)n;
	}
	close(fd);
	return true;
}

static int g_tz_offset = 0;   /* hours added to UTC when formatting times */
static int g_captcha_timeout = 0;  /* seconds for the login captcha, 0 = off */
static bool g_captcha_weak = false;  /* -captcha L: digits instead of art */
static int g_auth_timeout = 60;  /* -auth N: auth phase limit (s) */

static std::string fmt_time(long long t)
{
	if (t <= 0) return "-";
	time_t tt = (time_t)t + (time_t)g_tz_offset * 3600;
	struct tm tmv;
	gmtime_r(&tt, &tmv);
	char b[32];
	strftime(b, sizeof(b), "%Y%m%d%H%M", &tmv);
	return b;
}

/* ------------------------------------------------------------------ */
/* sandbox                                                             */
/* ------------------------------------------------------------------ */

struct Meta {
	std::string id;         /* unique, stable identity (survives renames) */
	std::string creator_ip;
	std::string editor_ip;
	long long creator_ts = 0;
	long long mtime_ts = 0;
};

struct Entry {
	std::string name;
	bool isdir = false;
	long long size = 0;
	Meta meta;
};

class Sandbox {
public:
	explicit Sandbox(const std::string &root) : root_(root) {}
	const std::string &root() const { return root_; }

	static std::string disk_path(const std::string &rel, char lastprefix)
	{
		std::string out;
		size_t i = 0;
		while (i < rel.size()) {
			size_t j = rel.find('/', i);
			bool last = (j == std::string::npos);
			std::string c = last ? rel.substr(i) : rel.substr(i, j - i);
			if (!out.empty()) out += "/";
			out += last ? (std::string(1, lastprefix) + c) : ("1" + c);
			if (last) break;
			i = j + 1;
		}
		return out;
	}
	std::string abs(const std::string &rel) const
	{
		return rel.empty() ? root_ : root_ + "/" + disk_path(rel, '1');
	}
	std::string abs_meta(const std::string &rel) const
	{
		return root_ + "/" + disk_path(rel, '0');
	}

	bool normalize(const std::string &base, const std::string &input,
	               std::string &out) const
	{
		std::string p = base;
		if (!input.empty() && input[0] == '/')
			p.clear();
		p += "/";
		p += input;
		std::vector<std::string> parts;
		size_t i = 0;
		while (i < p.size()) {
			size_t j = p.find('/', i);
			if (j == std::string::npos) j = p.size();
			std::string c = p.substr(i, j - i);
			i = j + 1;
			if (c.empty() || c == ".") continue;
			if (c == "..") {
				if (parts.empty()) return false;
				parts.pop_back();
				continue;
			}
			if (c.find('\0') != std::string::npos) return false;
			parts.push_back(c);
		}
		out.clear();
		for (size_t k = 0; k < parts.size(); k++) {
			if (k) out += "/";
			out += parts[k];
		}
		return true;
	}

	static bool valid_name(const std::string &n)
	{
		if (n.empty() || n == "." || n == "..") return false;
		if (n.find('/') != std::string::npos) return false;
		if (n.find('\0') != std::string::npos) return false;
		for (unsigned char c : n)                /* no control characters */
			if (c < 0x20 || c == 0x7F) return false;
		return true;
	}

	Meta read_meta(const std::string &rel) const
	{
		Meta m;
		std::string data;
		if (!read_file(abs_meta(rel), data))
			return m;
		size_t pos = 0;
		while (pos < data.size()) {
			size_t e = data.find('\n', pos);
			if (e == std::string::npos) e = data.size();
			std::string line = data.substr(pos, e - pos);
			pos = e + 1;
			size_t eq = line.find('=');
			if (eq == std::string::npos) continue;
			std::string k = line.substr(0, eq), v = line.substr(eq + 1);
			if (k == "creator_ip") m.creator_ip = v;
			else if (k == "editor_ip") m.editor_ip = v;
			else if (k == "creator_ts") m.creator_ts = atoll(v.c_str());
			else if (k == "mtime_ts") m.mtime_ts = atoll(v.c_str());
			else if (k == "id") m.id = v;
		}
		return m;
	}

	void write_meta(const std::string &rel, const Meta &m) const
	{
		std::string data = sfmt("id=%s\ncreator_ip=%s\ncreator_ts=%lld\neditor_ip=%s\nmtime_ts=%lld\n",
		                        m.id.c_str(), m.creator_ip.c_str(), m.creator_ts,
		                        m.editor_ip.c_str(), m.mtime_ts);
		write_file(abs_meta(rel), data);
	}

	/* Update the metadata of every ancestor directory (change propagates
	 * upward). */
	void touch_ancestors(const std::string &rel, const std::string &ip) const
	{
		std::string p = rel;
		for (;;) {
			size_t s = p.rfind('/');
			if (s == std::string::npos)
				break;
			p = p.substr(0, s);
			Meta m = read_meta(p);
			if (m.creator_ip.empty()) {
				m.creator_ip = ip;
				m.creator_ts = (long long)time(nullptr);
			}
			m.editor_ip = ip;
			m.mtime_ts = (long long)time(nullptr);
			write_meta(p, m);
		}
	}

	bool list(const std::string &rel, std::vector<Entry> &out) const
	{
		out.clear();
		DIR *d = opendir(abs(rel).c_str());
		if (!d) return false;
		struct dirent *de;
		while ((de = readdir(d)) != nullptr) {
			std::string dn = de->d_name;
			if (dn.size() < 2 || dn[0] != '1')
				continue;
			std::string name = dn.substr(1);
			Entry e;
			e.name = name;
			struct stat sb;
			std::string full = abs(rel) + "/" + dn;
			if (stat(full.c_str(), &sb) != 0)
				continue;
			e.isdir = S_ISDIR(sb.st_mode);
			e.size = e.isdir ? 0 : (long long)sb.st_size;
			e.meta = read_meta(rel.empty() ? name : rel + "/" + name);
			if (e.meta.id.empty())
				e.meta.id = e.name;   /* old sidecar: stable fallback */
			if (!e.meta.mtime_ts)
				e.meta.mtime_ts = (long long)sb.st_mtime;
			out.push_back(e);
		}
		closedir(d);
		std::sort(out.begin(), out.end(), [](const Entry &a, const Entry &b) {
			if (a.isdir != b.isdir) return a.isdir > b.isdir;
			return name_cmp(a.name, b.name) < 0;
		});
		return true;
	}

	bool exists(const std::string &rel) const
	{
		struct stat sb;
		return stat(abs(rel).c_str(), &sb) == 0;
	}
	bool is_dir(const std::string &rel) const
	{
		struct stat sb;
		return stat(abs(rel).c_str(), &sb) == 0 && S_ISDIR(sb.st_mode);
	}

	bool create_file(const std::string &rel, const std::string &ip, bool isdir)
	{
		if (isdir) {
			if (mkdir(abs(rel).c_str(), 0755) != 0 && errno != EEXIST)
				return false;
		} else {
			int fd = open(abs(rel).c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
			if (fd < 0) return false;
			close(fd);
		}
		Meta m;
		m.id = new_id();
		m.creator_ip = ip;
		m.editor_ip = ip;
		m.creator_ts = m.mtime_ts = (long long)time(nullptr);
		write_meta(rel, m);
		touch_ancestors(rel, ip);
		return true;
	}

	/* delete; returns 1 = fully removed, -1 = partially (locked files and
	 * their parent folders were kept), -2 = the entry itself is being
	 * edited by someone, 0 = failed.  The change propagates upward. */
	int remove_entry(const std::string &rel, const std::string &ip)
	{
		if (!is_dir(rel)) {
			if (filelock_held(rel))
				return -2;              /* a locked file cannot be deleted */
			if (unlink(abs(rel).c_str()) != 0)
				return 0;
			unlink(abs_meta(rel).c_str());
			touch_ancestors(rel, ip);
			return 1;
		}
		bool full = remove_tree_locked(rel);
		touch_ancestors(rel, ip);
		return full ? 1 : -1;   /* events are pushed per removed level */
	}

private:
	/* remove a tree, but keep locked files and every folder on their chain */
	bool remove_tree_locked(const std::string &rel)
	{
		std::vector<Entry> kids;
		list(rel, kids);
		bool all = true;
		for (auto &k : kids) {
			std::string krel = rel.empty() ? k.name : rel + "/" + k.name;
			if (k.isdir) {
				if (!remove_tree_locked(krel))
					all = false;
			} else {
				if (filelock_held(krel)) { all = false; continue; }
				unlink(abs(krel).c_str());
				unlink(abs_meta(krel).c_str());
			}
		}
		if (all) {
			unlink(abs_meta(rel).c_str());
			if (rmdir(abs(rel).c_str()) == 0) {
				/* this level really disappeared: sessions inside are pushed
				 * up to its parent; deeper deletions already pushed their own
				 * events, so sessions cascade up level by level */
				push_event(1, rel);
				return true;
			}
			return false;
		}
		return false;
	}

public:
	bool rename_entry(const std::string &from_rel, const std::string &to_rel,
	                  const std::string &ip)
	{
		if (exists(to_rel)) return false;
		if (::rename(abs(from_rel).c_str(), abs(to_rel).c_str()) != 0)
			return false;
		::rename(abs_meta(from_rel).c_str(), abs_meta(to_rel).c_str());
		/* make sure the renamed entry carries a stable id (upgrade old
		 * sidecars that predate ids) and record the move on itself */
		Meta m = read_meta(to_rel);
		if (m.id.empty())
			m.id = new_id();
		m.editor_ip = ip;
		m.mtime_ts = (long long)time(nullptr);
		write_meta(to_rel, m);
		/* a locked file keeps its lock under the new path */
		{
			std::lock_guard<std::mutex> lk(g_lock_mtx);
			if (g_filelocks.count(from_rel)) {
				g_filelocks.erase(from_rel);
				g_filelocks.insert(to_rel);
				g_lock_epoch++;
			}
		}
		/* both the source and the destination changed: propagate upward on
		 * both chains (mtime AND editor ip) */
		touch_ancestors(to_rel, ip);
		touch_ancestors(from_rel, ip);
		push_event(0, from_rel, to_rel);
		return true;
	}

	std::string read_content(const std::string &rel) const
	{
		std::string d;
		read_file(abs(rel), d);
		return d;
	}

	bool save_content(const std::string &rel, const std::string &data,
	                  const std::string &ip)
	{
		if (!write_file(abs(rel), data)) return false;
		Meta m = read_meta(rel);
		if (m.creator_ip.empty()) {
			m.creator_ip = ip;
			m.creator_ts = (long long)time(nullptr);
		}
		m.editor_ip = ip;
		m.mtime_ts = (long long)time(nullptr);
		write_meta(rel, m);
		touch_ancestors(rel, ip);
		return true;
	}

private:
	std::string root_;

	static bool remove_tree(const std::string &path)
	{
		DIR *d = opendir(path.c_str());
		if (!d)
			return unlink(path.c_str()) == 0;
		struct dirent *de;
		bool ok = true;
		while ((de = readdir(d)) != nullptr) {
			std::string n = de->d_name;
			if (n == "." || n == "..") continue;
			std::string p = path + "/" + n;
			struct stat sb;
			if (lstat(p.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) {
				if (!remove_tree(p)) ok = false;
			} else {
				if (unlink(p.c_str()) != 0) ok = false;
			}
		}
		closedir(d);
		if (rmdir(path.c_str()) != 0) ok = false;
		return ok;
	}
};

/* ------------------------------------------------------------------ */
/* parametric captcha art                                              */
/*                                                                     */
/* Each glyph is a skeleton of polylines whose stroke widths, slant and */
/* scale are randomised per captcha ("a fresh font every time").  The   */
/* shape is rasterised into a HIGH-RESOLUTION mask (S x S samples per   */
/* character cell); the OUTPUT grid is the character grid: for every    */
/* cell the algorithm looks at where the outline crosses the cell's     */
/* edges (sub-cell position via binary search), takes the first two     */
/* crossings as the local direction and quantises it to one of - | / \. */
/* Cells with fewer than two crossings stay blank, so the inside of a   */
/* thick stroke never turns into mush.                                  */
/* ------------------------------------------------------------------ */

struct ArtPt {
	float x, y;
};

static float art_rand(unsigned &s)
{
	s = s * 1103515245u + 12345u;
	return (float)((s >> 16) & 0x7FFF) / 32767.0f;
}

/* skeleton of one glyph: polylines in a 0..1 box (y down) */
static std::vector<std::vector<ArtPt>> glyph_skeleton(char ch)
{
	std::vector<std::vector<ArtPt>> g;
	auto pl = [&](std::initializer_list<ArtPt> pts) {
		g.push_back(std::vector<ArtPt>(pts.begin(), pts.end()));
	};
	switch (ch) {
	case 'b': pl({{.20f,0},{.20f,1}}); pl({{.20f,.50f},{.62f,.50f},{.80f,.64f},{.80f,.86f},{.62f,1},{.20f,1}}); break;
	case 'c': pl({{.80f,.22f},{.52f,0},{.24f,.22f},{.24f,.78f},{.52f,1},{.80f,.78f}}); break;
	case 'd': pl({{.80f,0},{.80f,1}}); pl({{.80f,.50f},{.38f,.50f},{.20f,.64f},{.20f,.86f},{.38f,1},{.80f,1}}); break;
	case 'e': pl({{.20f,.52f},{.80f,.52f}}); pl({{.80f,.52f},{.80f,.24f},{.52f,0},{.24f,.22f},{.24f,.78f},{.52f,1},{.80f,.80f}}); break;
	case 'f': pl({{.52f,.10f},{.52f,1}}); pl({{.20f,.30f},{.78f,.30f}}); pl({{.52f,.10f},{.38f,0},{.26f,.10f}}); break;
	case 'g': pl({{.78f,.26f},{.52f,.08f},{.26f,.26f},{.26f,.55f},{.52f,.74f},{.78f,.55f}}); pl({{.78f,.26f},{.78f,.84f},{.58f,1},{.30f,1}}); break;
	case 'h': pl({{.20f,-.06f},{.20f,1}}); pl({{.20f,.46f},{.50f,.24f},{.80f,.46f}}); pl({{.80f,.46f},{.80f,1}}); break;
	case 'j': pl({{.62f,0},{.62f,.78f},{.44f,1},{.22f,.82f}}); break;
	case 'k': pl({{.20f,0},{.20f,1}}); pl({{.78f,.10f},{.20f,.56f}}); pl({{.36f,.46f},{.82f,1}}); break;
	case 'm': pl({{.10f,0},{.10f,1}}); pl({{.50f,0},{.50f,1}}); pl({{.90f,0},{.90f,1}});
	          pl({{.10f,.30f},{.30f,.14f},{.50f,.30f}}); pl({{.50f,.30f},{.70f,.14f},{.90f,.30f}}); break;
	case 'n': pl({{.20f,0},{.20f,1}}); pl({{.20f,.26f},{.50f,.02f},{.80f,.26f}}); pl({{.80f,.26f},{.80f,1}}); break;
	case 'p': pl({{.20f,0},{.20f,1}}); pl({{.20f,.04f},{.55f,.04f},{.80f,.17f},{.80f,.40f},{.55f,.52f},{.20f,.52f}}); break;
	case 'q': pl({{.80f,0},{.80f,.94f}}); pl({{.80f,.04f},{.45f,.04f},{.20f,.17f},{.20f,.40f},{.45f,.52f},{.80f,.52f}}); pl({{.80f,.94f},{.96f,1}}); break;
	case 'r': pl({{.26f,0},{.26f,1}}); pl({{.26f,.34f},{.52f,.16f},{.80f,.30f}}); break;
	case 's': pl({{.80f,.20f},{.52f,0},{.26f,.16f},{.26f,.40f},{.52f,.50f},{.76f,.60f},{.76f,.84f},{.52f,1},{.20f,.80f}}); break;
	case 't': pl({{.50f,.06f},{.50f,.88f},{.70f,1}}); pl({{.20f,.22f},{.80f,.22f}}); break;
	case 'u': pl({{.20f,0},{.20f,.78f},{.32f,.94f},{.68f,.94f},{.80f,.78f},{.80f,0}}); break;
	case 'v': pl({{.16f,0},{.50f,1},{.84f,0}}); break;
	case 'w': pl({{.10f,0},{.30f,1},{.50f,.40f},{.70f,1},{.90f,0}}); break;
	case 'x': pl({{.20f,0},{.80f,1}}); pl({{.80f,0},{.20f,1}}); break;
	case 'y': pl({{.20f,0},{.50f,.60f}}); pl({{.80f,0},{.50f,.60f},{.50f,1}}); break;
	case 'z': pl({{.20f,.05f},{.80f,.05f},{.20f,.95f},{.80f,.95f}}); break;
	case '2': pl({{.20f,.22f},{.52f,0},{.80f,.22f},{.80f,.42f},{.20f,.90f},{.20f,.95f},{.80f,.95f}}); break;
	case '3': pl({{.20f,.14f},{.52f,0},{.80f,.14f},{.80f,.40f},{.52f,.50f},{.80f,.60f},{.80f,.86f},{.52f,1},{.20f,.86f}}); break;
	case '4': pl({{.72f,0},{.20f,.60f},{.86f,.60f}}); pl({{.72f,0},{.72f,1}}); break;
	case '6': pl({{.76f,.10f},{.52f,0},{.26f,.20f},{.20f,.60f},{.26f,.90f},{.52f,1},{.76f,.90f},{.80f,.66f},{.52f,.50f},{.26f,.60f}}); break;
	case '7': pl({{.20f,.05f},{.80f,.05f},{.40f,1}}); break;
	case '9': pl({{.78f,.26f},{.52f,.08f},{.26f,.26f},{.26f,.52f},{.52f,.72f},{.78f,.52f},{.78f,.26f}}); pl({{.78f,.52f},{.78f,.86f},{.54f,1}}); break;
	default:  pl({{.25f,.25f},{.75f,.75f}}); pl({{.75f,.25f},{.25f,.75f}}); break;
	}
	return g;
}

static void art_disc(std::vector<unsigned char> &m, int W, int H,
                     float cx, float cy, float r)
{
	int x0 = (int)floorf(cx - r), x1 = (int)ceilf(cx + r);
	int y0 = (int)floorf(cy - r), y1 = (int)ceilf(cy + r);
	for (int y = y0; y <= y1; y++) {
		if (y < 0 || y >= H) continue;
		for (int x = x0; x <= x1; x++) {
			if (x < 0 || x >= W) continue;
			float dx = x - cx, dy = y - cy;
			if (dx * dx + dy * dy <= r * r)
				m[(size_t)y * W + x] = 1;
		}
	}
}

static void art_stamp_seg(std::vector<unsigned char> &m, int W, int H,
                          float ax, float ay, float bx, float by, float r)
{
	float dx = bx - ax, dy = by - ay;
	float len = sqrtf(dx * dx + dy * dy);
	int steps = (int)(len * 2.0f) + 1;
	for (int s = 0; s <= steps; s++) {
		float t = (float)s / (float)steps;
		art_disc(m, W, H, ax + dx * t, ay + dy * t, r);
	}
}

/* sub-cell position where the mask value changes along one cell edge */
static float art_edge_cross(const std::vector<unsigned char> &m, int W, int H,
                            bool horizontal, int fixed, int a, int b)
{
	if (a >= b)
		return -1.0f;
	auto val = [&](int x, int y) {
		if (x < 0 || y < 0 || x >= W || y >= H) return 0;
		return (int)m[(size_t)y * W + x];
	};
	int va = horizontal ? val(a, fixed) : val(fixed, a);
	int vb = horizontal ? val(b, fixed) : val(fixed, b);
	if (va == vb)
		return -1.0f;
	int lo = a, hi = b;
	while (lo < hi - 1) {
		int mid = (lo + hi) / 2;
		int vm = horizontal ? val(mid, fixed) : val(fixed, mid);
		if (vm == va) lo = mid; else hi = mid;
	}
	return (lo + hi) / 2.0f;
}

/* 4-way quantisation of a direction into line characters */
static char art_quant(float dx, float dy)
{
	float ang = atan2f(dy, dx) * 57.29578f;
	float a = fmodf(fabsf(ang), 180.0f);
	if (a < 22.5f || a > 157.5f)
		return '-';
	if (a < 67.5f)
		return (ang > 0) ? '\\' : '/';
	if (a < 112.5f)
		return '|';
	return (ang > 0) ? '/' : '\\';
}

static std::vector<std::string> make_captcha_art(const std::string &code,
                                                 int W, int H, unsigned seed)
{
	std::vector<std::string> out;
	if (W < 16 || H < 5 || code.empty())
		return out;
	const int S = 8;                       /* samples per character cell */
	int n = (int)code.size();
	float slot = (float)W / std::max(4, n);   /* one char per slot */
	int gh = (int)(H * 0.85f);
	if (gh < 6)
		gh = 6;
	int cells_h = gh + 3;
	int cells_w = W + 2;

	/* per glyph: horizontal/vertical size multiplied by a random factor
	 * (0.5 .. 0.8), then the glyphs are placed left to right with random
	 * gaps so they never overlap */
	std::vector<float> sx(n), sy(n), gwid(n), ghei(n);
	float base_gw = slot * 0.9f;
	float base_gh = (float)gh;
	float sum_w = 0.0f;
	for (int i = 0; i < n; i++) {
		sx[i] = 0.5f + art_rand(seed) * 0.3f;
		sy[i] = 0.5f + art_rand(seed) * 0.3f;
		gwid[i] = base_gw * sx[i];
		ghei[i] = base_gh * sy[i];
		sum_w += gwid[i];
	}
	/* shrink the base width if the glyphs plus minimal gaps do not fit */
	float need = sum_w + (n + 1) * 0.5f;
	if (need > (float)W) {
		float k = ((float)W - (n + 1) * 0.5f) / sum_w;
		if (k < 0.2f)
			k = 0.2f;
		sum_w = 0.0f;
		for (int i = 0; i < n; i++) {
			gwid[i] *= k;
			ghei[i] *= k;
			sum_w += gwid[i];
		}
	}
	/* distribute the leftover width as random gaps (plus outer margins) */
	float leftover = (float)W - sum_w;
	if (leftover < (n + 1) * 0.5f)
		leftover = (n + 1) * 0.5f;
	std::vector<float> gap(n + 1);
	float wsum = 0.0f;
	for (int i = 0; i <= n; i++) {
		gap[i] = 0.2f + art_rand(seed);
		wsum += gap[i];
	}
	for (int i = 0; i <= n; i++)
		gap[i] = gap[i] / wsum * leftover;

	int FW = cells_w * S, FH = cells_h * S;
	std::vector<unsigned char> m((size_t)FW * FH, 0);
	float cur_x = gap[0];

	for (int i = 0; i < n; i++) {
		float vw = 0.14f;   /* uniform stroke width */
		float hw = 0.14f;
		float slant = (art_rand(seed) * 2 - 1) * 0.18f;
		float ox = cur_x;
		float oy = art_rand(seed) * (float)(cells_h - ghei[i] - 2.0f);
		if (oy < 0.0f)
			oy = 0.0f;
		std::vector<std::vector<ArtPt>> sk = glyph_skeleton(code[i]);
		for (auto &pl : sk) {
			for (size_t k = 0; k + 1 < pl.size(); k++) {
				ArtPt a = pl[k], b = pl[k + 1];
				float ax = ((a.x + a.y * slant) * gwid[i] + ox) * S;
				float ay = (a.y * ghei[i] + oy) * S;
				float bx = ((b.x + b.y * slant) * gwid[i] + ox) * S;
				float by = (b.y * ghei[i] + oy) * S;
				float ddx = bx - ax, ddy = by - ay;
				float dl = sqrtf(ddx * ddx + ddy * ddy);
				float h = (dl > 0.1f && fabsf(ddx / dl) > fabsf(ddy / dl))
				              ? hw : vw;
				art_stamp_seg(m, FW, FH, ax, ay, bx, by,
				              h * gwid[i] * S * 0.5f);
			}
		}
		cur_x += gwid[i] + gap[i + 1];
	}
	/* per character cell: classify the crossings by the edge they are on
	 * (top/bottom/left/right); opposite edges give - or |, adjacent edges
	 * give the diagonal that connects them */
	for (int cy = 0; cy < cells_h; cy++) {
		std::string line;
		for (int cx = 0; cx < cells_w; cx++) {
			int x0 = cx * S, y0 = cy * S, x1 = x0 + S, y1 = y0 + S;
			bool eT = false, eB = false, eL = false, eR = false;
			float tT = 0, tB = 0, tL = 0, tR = 0;
			float t = art_edge_cross(m, FW, FH, true, y0, x0, x1);
			if (t >= 0) { eT = true; tT = t; }
			t = art_edge_cross(m, FW, FH, true, y1, x0, x1);
			if (t >= 0) { eB = true; tB = t; }
			t = art_edge_cross(m, FW, FH, false, x0, y0, y1);
			if (t >= 0) { eL = true; tL = t; }
			t = art_edge_cross(m, FW, FH, false, x1, y0, y1);
			if (t >= 0) { eR = true; tR = t; }
			int cnt = (eT ? 1 : 0) + (eB ? 1 : 0) + (eL ? 1 : 0) + (eR ? 1 : 0);
			/* direction between two crossings: order them top-to-bottom so
			 * the slash sign is consistent with the screen (y grows down) */
			auto dirof = [&](float xa, float ya, float xb, float yb) {
				if (yb < ya || (yb == ya && xb < xa)) {
					float tx = xa; xa = xb; xb = tx;
					float ty = ya; ya = yb; yb = ty;
				}
				return art_quant(xb - xa, yb - ya);
			};
			char ch = ' ';
			if (cnt == 2) {
				if (eT && eB) {
					ch = '|';
				} else if (eL && eR) {
					ch = '-';
				} else if (eT && eL) {
					ch = dirof(tT, (float)y0, (float)x0, tL);
				} else if (eT && eR) {
					ch = dirof(tT, (float)y0, (float)x1, tR);
				} else if (eB && eL) {
					ch = dirof(tB, (float)y1, (float)x0, tL);
				} else {                     /* eB && eR */
					ch = dirof(tB, (float)y1, (float)x1, tR);
				}
			} else if (cnt > 2) {
				/* several crossings: connect the two that are farthest
				 * apart (a corner cell belongs to one direction) */
				std::vector<std::pair<float, float>> p;
				if (eT) p.push_back({tT, (float)y0});
				if (eB) p.push_back({tB, (float)y1});
				if (eL) p.push_back({(float)x0, tL});
				if (eR) p.push_back({(float)x1, tR});
				float best = -1;
				for (size_t i = 0; i < p.size(); i++)
					for (size_t k = i + 1; k < p.size(); k++) {
						float ddx = p[i].first - p[k].first;
						float ddy = p[i].second - p[k].second;
						float d2 = ddx * ddx + ddy * ddy;
						if (d2 > best) {
							best = d2;
							ch = dirof(p[i].first, p[i].second,
							           p[k].first, p[k].second);
						}
					}
			}
			line += ch;
		}
		out.push_back(line);
	}
	/* a thick stroke's outline can put two identical slashes side by side;
	 * collapse such runs to a single slash (keeping the row width) */
	for (auto &l : out) {
		for (size_t i = 1; i < l.size(); i++) {
			char c = l[i];
			if ((c != '/' && c != '\\') || l[i - 1] != c)
				continue;
			size_t k = i;
			while (k < l.size() && l[k] == c) {
				l[k] = ' ';
				k++;
			}
		}
	}
	/* the same for slashes stacked vertically: keep the upper one */
	for (size_t y = 1; y < out.size(); y++)
		for (size_t x = 0; x < out[y].size() && x < out[y - 1].size(); x++) {
			char c = out[y][x];
			if ((c == '/' || c == '\\') && out[y - 1][x] == c)
				out[y][x] = ' ';
		}
	/* trim empty borders */
	int maxx = -1, maxy = -1, minx = cells_w, miny = cells_h;
	for (int y = 0; y < (int)out.size(); y++)
		for (int x = 0; x < (int)out[y].size(); x++)
			if (out[y][x] != ' ') {
				if (x > maxx) maxx = x;
				if (y > maxy) maxy = y;
				if (x < minx) minx = x;
				if (y < miny) miny = y;
			}
	if (maxx < 0) {
		out.clear();
		out.push_back("   " + code);
		return out;
	}
	std::vector<std::string> trimmed;
	for (int y = miny; y <= maxy; y++)
		trimmed.push_back(out[y].substr(minx, maxx - minx + 1));
	return trimmed;
}

/* ------------------------------------------------------------------ */
/* UI                                                                  */
/* ------------------------------------------------------------------ */

/* minimum widths of the entry cells: name size created edited creator editor */
static const int CELL_MIN[6] = {18, 6, 12, 12, 15, 15};

enum class Key {
	None, Resize, Tick, Update, Redraw, Up, Down, Left, Right, Home, End, PageUp, PageDown,
	CtrlB,
	Delete, Backspace, Enter, Esc, Tab, Char, CtrlC, CtrlS, CtrlG, CtrlL, CtrlD
};
struct KeyEvent {
	Key key = Key::None;
	std::string text;
};

static void channel_write_all(ssh_channel ch, const std::string &s);

class UI {
public:
	UI(Sandbox &sb, const std::string &ip, ssh_session session)
	    : sb_(sb), ip_(ip), session_(session) {}

	void run(ssh_channel ch, int cols, int rows);

private:
	Sandbox &sb_;
	std::string ip_;
	ssh_session session_;
	ssh_channel ch_ = nullptr;
	std::string cwd_;
	std::vector<Entry> entries_;
	int sel_ = 0;
	int top_ = 0;
	int cols_ = 80, rows_ = 24;
	int main_cols_ = 79;                /* content width (cols_ - scrollbar) */

	enum Mode { LIST, EDITOR, PROMPT, CONFIRM, CAPTCHA } mode_ = LIST;
	Mode base_ = LIST;   /* content view behind a prompt/confirm */
	std::string status_;

	Mode content_view() const
	{
		return (mode_ == PROMPT || mode_ == CONFIRM) ? base_ : mode_;
	}

	/* editor */
	std::string edit_rel_;
	std::vector<std::string> lines_;
	int cy_ = 0, cx_ = 0, etop_ = 0;   /* etop_ = first visible display line */
	int goal_col_ = -1;                 /* remembered column for vertical moves */
	bool dirty_ = false;
	int anchor_logical_ = 0;            /* logical line at the top (resize anchor) */
	int last_w_ = 0;
	int name_scroll_ = 0;               /* marquee offset for the selected name */
	int title_scroll_ = 0;              /* marquee offset for the title bar */
	int msg_scroll_ = 0;                /* marquee offset for the message bar */
	std::string msg_shown_;             /* message the scroll offset belongs to */
	int sort_mode_ = 0;                 /* 0 = name, 1 = time */
	std::string edit_lock_;             /* rel path currently locked for editing */

	/* prompt/confirm */
	int prompt_action_ = 0;
	std::string prompt_label_, prompt_buf_;
	size_t prompt_cx_ = 0;      /* byte cursor in prompt_buf_ */
	int prompt_scroll_ = 0;     /* horizontal scroll (display cols) */
	int prompt_curcol_ = 0;     /* cursor column inside the visible window */
	int confirm_action_ = 0;
	std::string confirm_word_, confirm_what_;

	/* login captcha (only when -captcha is given) */
	std::string captcha_code_;
	time_t captcha_deadline_ = 0;
	bool captcha_weak_ = false;
	std::vector<std::string> captcha_art_;
	std::vector<std::string> captcha_screen_;   /* noise + edges + art */
	int captcha_art_w_ = 0, captcha_art_h_ = 0;
	bool quit_ = false;
	void startup_flash();
	void draw_captcha(std::string &s);
	void handle_captcha(const KeyEvent &ev);
	void captcha_regen(int w, int h);
	void captcha_new_code();

	std::string inbuf_;
	unsigned long long seen_version_ = 0;
	unsigned long long seen_event_id_ = 0;  /* last consumed path-event id */
	unsigned long long seen_bell_id_ = 0;   /* last consumed bell id */
	unsigned long long seen_msg_id_ = 0;    /* last consumed broadcast message */
	unsigned long long seen_online_ = 0;  /* last broadcast online count epoch */
	unsigned long long seen_lock_ = 0;    /* last broadcast lock epoch */
	unsigned long long sid_ = 0;          /* this session's id in g_sessions */

	/* layout results */
	int keylines_ = 1;
	int main_top_ = 1, main_bottom_ = 1;
	int msg_row_ = 1, input_row_ = 1;
	int last_cols_ = -1, last_rows_ = -1;   /* for full redraw on resize */
	std::vector<std::string> keyline_cache_;

	void layout();
	void render();
	void draw_list(std::string &s);
	void draw_editor(std::string &s);
	void draw_keys(std::string &s);
	void draw_msg(std::string &s);
	void draw_input(std::string &s);
	void put(std::string &s, int row, int col, const std::string &text);
	void put_fill(std::string &s, int row, const std::string &text, int w);

	bool next_key(KeyEvent &ev);
	void handle_list(const KeyEvent &ev);
	void editor_remember_goal();
	void handle_editor(const KeyEvent &ev);
	void handle_prompt(const KeyEvent &ev);
	void handle_confirm(const KeyEvent &ev);
	bool poll_resize();

	void refresh(bool keep_sel = true);
	void ensure_sel_visible();
	void process_events();
	void process_bells();
	void process_messages();
	int here_count() const;
	void after_change();
	void sort_entries();
	void clamp_sel_top();
	void resort();

	void open_prompt(int action, const std::string &label, const std::string &prefill);
	void open_confirm(int action, const std::string &what);
	void do_prompt_commit();

	void editor_load(const std::string &rel);
	void editor_save();
	void leave_editor();
	int editor_line_count() const { return (int)lines_.size(); }
	std::vector<std::pair<int, int>> editor_display(); /* (logical, chunkstart) */
	void entry_lines(std::vector<std::vector<int>> &lines) const;
	void cell_widths(const std::vector<int> &cells, int w[6]) const;
	bool marquee_active() const;
	std::string title_text() const;
	void draw_scrollbar(std::string &s, int first, int count, int total);
};

/* pad a UTF-8 string to exactly `w` display columns */
static std::string pad_to(const std::string &s, int w, bool right)
{
	std::string t = u8clip(s, w);
	int pad = w - u8width(t);
	if (pad < 0) pad = 0;
	if (right) return std::string(pad, ' ') + t;
	return t + std::string(pad, ' ');
}

/* ---- output helpers ---- */

void UI::put(std::string &s, int row, int col, const std::string &text)
{
	s += sfmt("\x1b[%d;%dH", row, col);
	s += text;
}

/* write text padded/clipped to exactly `w` display columns, filling `w` */
void UI::put_fill(std::string &s, int row, const std::string &text, int w)
{
	std::string t = u8clip(text, w);
	int pad = w - u8width(t);
	if (pad < 0) pad = 0;
	s += sfmt("\x1b[%d;1H%s", row, t.c_str());
	for (int i = 0; i < pad; i++)
		s += " ";
}

/* ---- layout ---- */

void UI::layout()
{
	if (cols_ < 12) cols_ = 12;
	if (rows_ < 6) rows_ = 6;
	main_cols_ = cols_ - 1;   /* rightmost column is the scrollbar */

	/* key bar: wrap the hints into lines of `cols_` */
	Mode cv = content_view();
	std::vector<std::string> hints;
	if (mode_ == CAPTCHA)
		hints = {"Enter:ok", "Esc:quit"};
	else if (mode_ == PROMPT || mode_ == CONFIRM)
		hints = {"Enter:ok", "Esc:cancel"};
	else if (cv == EDITOR)
		hints = {"^S:save", "^G:goto", "Esc:back"};
	else
		hints = {"n:new", "N:mkdir", "m:move", "d:delete", "Enter:open",
		         "g:goto", "b:bel", "B:bcast", "^B:bel-all", "t:time", "s:name",
		         "r:reload", "Esc:back", "q:quit"};

	std::vector<std::vector<std::string>> lines;
	std::vector<std::string> cur;
	int curw = 0;
	for (auto &h : hints) {
		int hw = u8width(h);
		/* after adding h, the line has cur.size()+1 hints and needs one
		 * gap (>=1) after each */
		if (!cur.empty() && curw + hw + (int)cur.size() + 1 > cols_) {
			lines.push_back(cur);
			cur.clear();
			curw = 0;
		}
		cur.push_back(h);
		curw += hw;
	}
	if (!cur.empty() || lines.empty())
		lines.push_back(cur);
	keyline_cache_.clear();
	for (auto &ln : lines) {
		int n = (int)ln.size();
		if (n == 0) { keyline_cache_.push_back(""); continue; }
		int hintsum = 0;
		for (auto &h : ln) hintsum += u8width(h);
		int gap = cols_ - hintsum;
		if (gap < n) gap = n;
		int base = gap / n, rem = gap % n;
		std::string out;
		for (int i = 0; i < n; i++) {
			out += ln[i];
			int g = base + (i < rem ? 1 : 0);
			if (g < 1) g = 1;
			out += std::string(g, ' ');
		}
		keyline_cache_.push_back(out);
	}
	keylines_ = (int)keyline_cache_.size();

	input_row_ = rows_;
	msg_row_ = rows_ - 1;
	/* list: title + N-line column header; editor/captcha: title only */
	if (cv == EDITOR || mode_ == CAPTCHA) {
		main_top_ = 2;
	} else {
		std::vector<std::vector<int>> elines;
		entry_lines(elines);
		main_top_ = 2 + (int)elines.size();
	}
	main_bottom_ = rows_ - 2 - keylines_;
	if (main_bottom_ < main_top_)
		main_bottom_ = main_top_;
}

void UI::sort_entries()
{
	if (sort_mode_ == 1) {
		std::stable_sort(entries_.begin(), entries_.end(),
		                 [](const Entry &a, const Entry &b) {
			if (a.meta.mtime_ts != b.meta.mtime_ts)
				return a.meta.mtime_ts > b.meta.mtime_ts;
			return name_cmp(a.name, b.name) < 0;
		});
	} else {
		std::sort(entries_.begin(), entries_.end(),
		          [](const Entry &a, const Entry &b) {
			return name_cmp(a.name, b.name) < 0;
		});
	}
}

void UI::clamp_sel_top()
{
	if (entries_.empty()) { sel_ = top_ = 0; return; }
	if (sel_ >= (int)entries_.size()) sel_ = (int)entries_.size() - 1;
	if (sel_ < 0) sel_ = 0;
	if (top_ >= (int)entries_.size()) top_ = (int)entries_.size() - 1;
	if (top_ < 0) top_ = 0;
}

/* Re-sort; try to bring the SELECTED entry back to the screen row it had
 * before sorting (not to the first line of the viewport). */
void UI::resort()
{
	std::string selid;
	int oldsel = sel_, oldtop = top_;
	if (sel_ >= 0 && sel_ < (int)entries_.size())
		selid = entries_[sel_].meta.id;
	sort_entries();
	int idx = -1;
	if (!selid.empty())
		for (int i = 0; i < (int)entries_.size(); i++)
			if (entries_[i].meta.id == selid) { idx = i; break; }
	if (idx < 0) {
		clamp_sel_top();
		return;
	}
	/* same relative row on screen as before */
	int relrow = oldsel - oldtop;
	top_ = idx - relrow;
	sel_ = idx;
	layout();
	std::vector<std::vector<int>> el;
	entry_lines(el);
	int hgt = (int)el.size();
	int mainh = main_bottom_ - main_top_ + 1;
	if (mainh < 1) mainh = 1;
	int vis = mainh / hgt;
	if (vis < 1) vis = 1;
	int total = (int)entries_.size();
	if (total <= vis) top_ = 0;
	else if (top_ > total - vis) top_ = total - vis;
	if (top_ < 0) top_ = 0;
}

void UI::ensure_sel_visible()
{
	layout();
	std::vector<std::vector<int>> el;
	entry_lines(el);
	int hgt = (int)el.size();
	int mainh = main_bottom_ - main_top_ + 1;
	if (mainh < 1) mainh = 1;
	int vis = mainh / hgt;
	if (vis < 1) vis = 1;
	if (sel_ < top_) top_ = sel_;
	if (sel_ >= top_ + vis) top_ = sel_ - vis + 1;
	if (top_ < 0) top_ = 0;
}

/* ring our terminal for every bell addressed to us (also while editing) */
void UI::process_bells()
{
	if (g_bell_seq.load(std::memory_order_relaxed) == seen_bell_id_)
		return;
	std::vector<BellEvent> evs;
	{
		std::lock_guard<std::mutex> lk(g_bell_mtx);
		for (auto it = g_bells.rbegin(); it != g_bells.rend(); ++it) {
			if (it->id <= seen_bell_id_)
				break;
			evs.push_back(*it);
		}
		seen_bell_id_ = g_bell_seq.load();
	}
	std::reverse(evs.begin(), evs.end());
	for (auto &b : evs)
		if (b.type == 1 || b.dir == cwd_)   /* exactly this directory */
			channel_write_all(ch_, "\a");
}

/* a broadcast message changes the message bar of every session */
void UI::process_messages()
{
	if (mode_ == CAPTCHA) {          /* not logged in yet: ignore broadcasts */
		seen_msg_id_ = g_msg_seq.load();
		return;
	}
	if (g_msg_seq.load(std::memory_order_relaxed) == seen_msg_id_)
		return;
	std::vector<BcastEvent> evs;
	{
		std::lock_guard<std::mutex> lk(g_msg_mtx);
		for (auto it = g_msgs.rbegin(); it != g_msgs.rend(); ++it) {
			if (it->id <= seen_msg_id_)
				break;
			evs.push_back(*it);
		}
		seen_msg_id_ = g_msg_seq.load();
	}
	if (!evs.empty()) {
		const BcastEvent &b = evs.back();      /* newest wins */
		status_ = "[" + b.from + "] " + b.text;
	}
}

/* sessions sitting in exactly this directory (subdirectories excluded) */
int UI::here_count() const
{
	std::lock_guard<std::mutex> lk(g_sess_mtx);
	int n = 0;
	for (auto &kv : g_sessions)
		if (kv.second == cwd_)
			n++;
	return n;
}

/* apply global path events (rename / delete) to this session's paths */
void UI::process_events()
{
	std::vector<PathEvent> evs;
	{
		std::lock_guard<std::mutex> lk(g_ev_mtx);
		for (auto it = g_events.rbegin(); it != g_events.rend(); ++it) {
			if (it->id <= seen_event_id_)
				break;                 /* everything before is seen too */
			evs.push_back(*it);
		}
		seen_event_id_ = g_ev_seq.load();
	}
	std::reverse(evs.begin(), evs.end());   /* apply in chronological order */
	auto under = [](const std::string &p, const std::string &pre) {
		return p == pre ||
		       (p.size() > pre.size() &&
		        p.compare(0, pre.size(), pre) == 0 && p[pre.size()] == '/');
	};
	for (auto &e : evs) {
		if (e.type == 0) {
			/* moved: rewrite cwd / open editor path (locks already re-keyed) */
			if (under(cwd_, e.a)) {
				cwd_ = e.b + cwd_.substr(e.a.size());
				entries_.clear();
			}
			if (!edit_rel_.empty() && under(edit_rel_, e.a)) {
				edit_rel_ = e.b + edit_rel_.substr(e.a.size());
				edit_lock_ = edit_rel_;
			}
		} else if (e.type == 1) {
			/* a folder we had open (or a parent of it) was deleted:
			 * jump to its parent and tell the user */
			if (under(cwd_, e.a)) {
				size_t p = e.a.rfind('/');
				cwd_ = (p == std::string::npos) ? std::string() : e.a.substr(0, p);
				entries_.clear();
				status_ = "the open folder was deleted";
			}
		}
	}
}

void UI::refresh(bool keep_sel)
{
	(void)keep_sel;
	/* initial load: sorted view; a fresh directory defaults to time order */
	if (entries_.empty()) {
		sort_mode_ = 1;
		sb_.list(cwd_, entries_);
		sort_entries();
		sel_ = top_ = 0;
		clamp_sel_top();
		return;
	}
	/* identity is the unique id (renames keep the id -> same entry) */
	std::set<std::string> oldids;
	for (auto &e : entries_)
		oldids.insert(e.meta.id);
	std::string topid, selid;
	int oldsel = sel_;
	if (top_ >= 0 && top_ < (int)entries_.size())
		topid = entries_[top_].meta.id;
	if (sel_ >= 0 && sel_ < (int)entries_.size())
		selid = entries_[sel_].meta.id;

	std::vector<Entry> listed;
	sb_.list(cwd_, listed);

	/* survivors keep their (arbitrary) display order and are updated in
	 * place; deleted entries are dropped */
	std::map<std::string, size_t> pos;      /* id -> index in `listed` */
	for (size_t i = 0; i < listed.size(); i++)
		pos[listed[i].meta.id] = i;
	std::vector<Entry> kept, added;
	for (auto &e : entries_) {
		auto it = pos.find(e.meta.id);
		if (it != pos.end())
			kept.push_back(listed[it->second]);
	}
	for (auto &c : listed)
		if (!oldids.count(c.meta.id)) added.push_back(c);

	/* entering another directory: fresh sorted view, default time order */
	if (kept.empty()) {
		sort_mode_ = 1;
		entries_ = listed;
		sort_entries();
		sel_ = top_ = 0;
		clamp_sel_top();
		return;
	}

	/* anchor: bring the old viewport's first line back to the top */
	int newtop = 0;
	if (!topid.empty())
		for (int i = 0; i < (int)kept.size(); i++)
			if (kept[i].meta.id == topid) { newtop = i; break; }
	/* every new entry is inserted in front of the new first line: they become
	 * visible and push the first line back -> the "new new" first line */
	if (!added.empty()) {
		if (newtop > (int)kept.size()) newtop = (int)kept.size();
		kept.insert(kept.begin() + newtop, added.begin(), added.end());
	}
	entries_ = kept;
	top_ = newtop;

	/* cursor: the previously selected entry A decides the scroll.
	 * A inside the viewport -> keep it; A above -> first line; A below ->
	 * last line; A gone (deleted) -> keep the index so the screen position
	 * stays (deleting the last entry moves the cursor up one line) */
	int a_idx = -1;
	if (!selid.empty())
		for (int i = 0; i < (int)entries_.size(); i++)
			if (entries_[i].meta.id == selid) { a_idx = i; break; }
	if (a_idx >= 0) {
		sel_ = a_idx;
		ensure_sel_visible();
	} else {
		if (oldsel > (int)entries_.size() - 1) oldsel = (int)entries_.size() - 1;
		if (oldsel < 0) oldsel = 0;
		sel_ = oldsel;
		ensure_sel_visible();
	}
	clamp_sel_top();
}

void UI::after_change()
{
	bump_version();
	process_events();      /* our own move/delete may rewrite our paths */
	refresh();
	/* consume our own version bump: a second refresh() here would re-sort and
	 * jump the viewport to the new entry's sorted position */
	seen_version_ = get_version();
}

/* ---- list layout ---- */

/* a `w`-wide window into `s + "   "` repeated, starting at display col `off` */
static std::string cyclic_window(const std::string &s, int off, int w)
{
	std::string cyc = s + "   ";
	int W = u8width(cyc);
	if (W <= 0 || w <= 0)
		return "";
	off %= W;
	std::string out;
	int col = 0, taken = 0;
	for (int pass = 0; pass < 2 && taken < w; pass++) {
		for (size_t i = 0; i < cyc.size() && taken < w;) {
			size_t j = next_cluster(cyc, i);
			int cwp = cluster_width(cyc, i, j);
			if (col >= off) {
				out.append(cyc, i, j - i);
				taken += cwp;
			}
			col += cwp;
			i = j;
		}
	}
	return out;
}

void UI::entry_lines(std::vector<std::vector<int>> &lines) const
{
	lines.clear();
	std::vector<int> cur;
	int used = 0;
	for (int i = 0; i < 6; i++) {
		int w = CELL_MIN[i];
		int add = cur.empty() ? w : w + 1;
		if (!cur.empty() && used + add > main_cols_) {
			lines.push_back(cur);
			cur.clear();
			used = 0;
		}
		cur.push_back(i);
		used += cur.size() == 1 ? w : w + 1;
	}
	if (!cur.empty())
		lines.push_back(cur);
	if (lines.empty())
		lines.push_back(std::vector<int>{0});
}

void UI::cell_widths(const std::vector<int> &cells, int w[6]) const
{
	int n = (int)cells.size();
	int fixed = 0;
	for (int c : cells)
		fixed += CELL_MIN[c];
	int extra = main_cols_ - fixed - (n - 1);
	if (extra < 0) extra = 0;
	int base = extra / n, rem = extra % n;
	for (int k = 0; k < n; k++)
		w[cells[k]] = CELL_MIN[cells[k]] + base + (k < rem ? 1 : 0);
}

bool UI::marquee_active() const
{
	if (u8width(title_text()) > cols_)
		return true;
	if (u8width(sanitize_ctrl(status_)) > cols_)
		return true;   /* the message bar scrolls when too long */
	if (msg_scroll_ != 0)
		return true;
	if (content_view() != LIST || entries_.empty())
		return false;
	if (sel_ < 0 || sel_ >= (int)entries_.size())
		return false;
	std::vector<std::vector<int>> elines;
	entry_lines(elines);
	int w[6] = {0};
	cell_widths(elines[0], w);
	const Entry &e = entries_[sel_];
	std::string nm = sanitize_ctrl(e.name) + (e.isdir ? "/" : "");
	return u8width(nm) > w[0];
}

std::string UI::title_text() const
{
	if (mode_ == CAPTCHA) {
		int left = (int)(captcha_deadline_ - time(nullptr));
		if (left < 0) left = 0;
		return sanitize_ctrl(captcha_weak_
		    ? sfmt(" sshfm  low captcha   time left: %ds", left)
		    : sfmt(" sshfm  captcha   time left: %ds", left));
	}
	if (content_view() == EDITOR)
		return sanitize_ctrl(sfmt(" edit: %s   line %d/%d", edit_rel_.c_str(),
		                          cy_ + 1, editor_line_count()));
	return sanitize_ctrl(sfmt(" sshfm  /%s   [%s]   ol %d/%d", cwd_.c_str(),
	                          ip_.c_str(), here_count(), g_online.load()));
}

void UI::draw_scrollbar(std::string &s, int first, int count, int total)
{
	int h = main_bottom_ - main_top_ + 1;
	if (h < 1)
		return;
	if (total <= count || total <= 0) {
		for (int i = 0; i < h; i++)
			put(s, main_top_ + i, cols_, " ");
		return;
	}
	int thumb_h = h * count / total;
	if (thumb_h < 1) thumb_h = 1;
	if (thumb_h > h) thumb_h = h;
	int max_first = total - count;
	int thumb_top = (max_first > 0) ? first * (h - thumb_h) / max_first : 0;
	if (thumb_top < 0) thumb_top = 0;
	if (thumb_top + thumb_h > h) thumb_top = h - thumb_h;
	for (int i = 0; i < h; i++) {
		bool on = (i >= thumb_top && i < thumb_top + thumb_h);
		put(s, main_top_ + i, cols_, on ? "\xe2\x95\x91" : "\xe2\x94\x82");
	}
}

void UI::draw_list(std::string &s)
{
	int mainh = main_bottom_ - main_top_ + 1;
	if (mainh < 1) mainh = 1;

	std::vector<std::vector<int>> elines;
	entry_lines(elines);
	int hgt = (int)elines.size();
	if (hgt < 1) hgt = 1;
	static const char *hdr[6] = {"NAME", "SIZE", "CREATED", "EDITED",
	                             "CREATOR", "EDITOR"};

	/* title (marquee when too long) */
	std::string tt = title_text();
	if (u8width(tt) > cols_)
		tt = cyclic_window(tt, title_scroll_, cols_);
	s += "\x1b[7m";
	put_fill(s, 1, tt, cols_);
	s += "\x1b[0m";
	/* clear the whole header band, including the scrollbar column */
	for (int r = 2; r < main_top_; r++)
		put(s, r, 1, "\x1b[K");
	/* column header: same cell wrapping as the entries (any number of lines) */
	for (size_t li = 0; li < elines.size(); li++) {
		int w[6] = {0};
		cell_widths(elines[li], w);
		std::string h;
		for (size_t k = 0; k < elines[li].size(); k++) {
			int c = elines[li][k];
			h += pad_to(hdr[c], w[c], c == 1);
			if (k + 1 < elines[li].size()) h += " ";
		}
		put_fill(s, 2 + (int)li, h, main_cols_);
	}

	/* ensure the selection is visible */
	int vis = mainh / hgt;
	if (vis < 1) vis = 1;
	int above = (sel_ - top_) * hgt;
	if (above < 0) { top_ = sel_; above = 0; }
	while (above + hgt > mainh && top_ < sel_) { top_++; above -= hgt; }
	while (above + hgt > mainh && top_ > 0) { top_--; above += hgt; }
	/* clip: never leave empty slots in the viewport */
	{
		int total = (int)entries_.size();
		if (total <= vis) top_ = 0;
		else if (top_ > total - vis) top_ = total - vis;
		if (top_ < 0) top_ = 0;
	}

	int row = main_top_;
	for (int i = top_; i < (int)entries_.size() && row <= main_bottom_; i++) {
		const Entry &e = entries_[i];
		int w0[6] = {0};
		cell_widths(elines[0], w0);
		std::string cell[6];
		cell[0] = sanitize_ctrl(e.name) + (e.isdir ? "/" : "");
		cell[1] = e.isdir ? "<DIR>" : fmt_size(e.size, w0[1]);
		cell[2] = fmt_time(e.meta.creator_ts);
		cell[3] = fmt_time(e.meta.mtime_ts);
		cell[4] = e.meta.creator_ip;
		cell[5] = e.meta.editor_ip;
		bool selected = (i == sel_);
		std::string nmdisp = cell[0];
		if (selected && u8width(cell[0]) > w0[0])
			nmdisp = cyclic_window(cell[0], name_scroll_, w0[0]);
		/* a file being edited elsewhere: reverse video on its name */
		std::string rel = cwd_.empty() ? e.name : cwd_ + "/" + e.name;
		bool locked = !e.isdir && filelock_held(rel);
		if (locked && !selected)
			nmdisp = "\x1b[7m" + nmdisp + "\x1b[27m";
		else if (locked && selected)
			nmdisp = "\x1b[27m" + nmdisp + "\x1b[7m";   /* name stands out */
		if (selected)
			s += "\x1b[7m";
		for (size_t li = 0; li < elines.size() && row <= main_bottom_; li++) {
			int w[6] = {0};
			cell_widths(elines[li], w);
			std::string line;
			for (size_t k = 0; k < elines[li].size(); k++) {
				int c = elines[li][k];
				std::string txt = (li == 0 && c == 0) ? nmdisp : cell[c];
				line += pad_to(txt, w[c], c == 1);
				if (k + 1 < elines[li].size()) line += " ";
			}
			put_fill(s, row, line, main_cols_);
			row++;
		}
		if (selected)
			s += "\x1b[0m";
	}
	/* clear the rest of the main area */
	for (; row <= main_bottom_; row++)
		put(s, row, 1, "\x1b[K");
	draw_scrollbar(s, top_, vis, (int)entries_.size());
}

/* ---- editor layout ---- */

std::vector<std::pair<int, int>> UI::editor_display()
{
	int numw = 1;
	{
		int n = editor_line_count();
		int d = 0;
		while (n > 0) { d++; n /= 10; }
		numw = std::max(3, d) + 1;
	}
	int w = main_cols_ - numw - 1;   /* reserve one column for the cursor */
	if (w < 1) w = 1;
	std::vector<std::pair<int, int>> out;   /* (logical line, byte offset in line) */
	for (int li = 0; li < editor_line_count(); li++) {
		std::vector<std::string> chunks = u8wrap(sanitize_ctrl(lines_[li]), w);
		size_t off = 0;
		for (size_t ci = 0; ci < chunks.size(); ci++) {
			out.push_back({li, (int)off});
			off += chunks[ci].size();
		}
	}
	return out;
}

void UI::draw_editor(std::string &s)
{
	/* title (marquee when too long; keys live in the bottom key bar) */
	std::string tt = title_text();
	if (u8width(tt) > cols_)
		tt = cyclic_window(tt, title_scroll_, cols_);
	s += "\x1b[7m";
	put_fill(s, 1, tt, cols_);
	s += "\x1b[0m";

	int mainh = main_bottom_ - main_top_ + 1;
	if (mainh < 1) mainh = 1;
	int numw = 1;
	{
		int n = editor_line_count();
		int d = 0;
		while (n > 0) { d++; n /= 10; }
		numw = std::max(3, d) + 1;
	}
	int w = main_cols_ - numw - 1;   /* reserve one column for the cursor */
	if (w < 1) w = 1;

	std::vector<std::pair<int, int>> disp = editor_display();

	/* resize anchor: keep the logical line that was at the top */
	if (w != last_w_) {
		for (int k = 0; k < (int)disp.size(); k++)
			if (disp[k].first == anchor_logical_) { etop_ = k; break; }
		last_w_ = w;
	}

	/* cursor display position */
	int cdisp = 0;
	{
		int n = 0;
		for (int li = 0; li < cy_; li++) {
			std::vector<std::string> c = u8wrap(sanitize_ctrl(lines_[li]), w);
			n += (int)c.size();
		}
		std::vector<std::string> c = u8wrap(sanitize_ctrl(lines_[cy_]), w);
		int col = u8width(sanitize_ctrl(lines_[cy_]).substr(0, cx_));
		int ci = (w > 0) ? col / w : 0;
		if (ci >= (int)c.size()) ci = (int)c.size() - 1;
		cdisp = n + ci;
	}
	if (cdisp < etop_) etop_ = cdisp;
	if (cdisp >= etop_ + mainh) etop_ = cdisp - mainh + 1;
	if (etop_ < 0) etop_ = 0;
	/* clip: never leave empty slots in the viewport (best-effort anchors) */
	{
		int total = (int)disp.size();
		if (total <= mainh) etop_ = 0;
		else if (etop_ > total - mainh) etop_ = total - mainh;
		if (etop_ < 0) etop_ = 0;
	}

	for (int i = 0; i < mainh; i++) {
		int di = etop_ + i;
		int row = main_top_ + i;
		if (di >= (int)disp.size()) {
			put(s, row, 1, "\x1b[K");
			continue;
		}
		int li = disp[di].first;
		int off = disp[di].second;
		std::vector<std::string> chunks = u8wrap(sanitize_ctrl(lines_[li]), w);
		/* find the chunk index for this display line */
		int ci = 0, acc = off;
		(void)acc;
		{
			int seen = 0;
			for (int k = 0; k < (int)disp.size(); k++) {
				if (disp[k].first == li) {
					if (k == di) break;
					seen++;
				}
			}
			ci = seen;
		}
		std::string chunk = (ci < (int)chunks.size()) ? chunks[ci] : "";
		std::string num = (ci == 0) ? sfmt("%*d ", numw - 1, li + 1) : std::string(numw, ' ');
		put(s, row, 1, sfmt("\x1b[K%s%s", num.c_str(), chunk.c_str()));
	}
	draw_scrollbar(s, etop_, mainh, (int)disp.size());
	if (etop_ < (int)disp.size())
		anchor_logical_ = disp[etop_].first;
}

/* ---- bottom bars ---- */

void UI::draw_keys(std::string &s)
{
	for (int i = 0; i < keylines_ && i < (int)keyline_cache_.size(); i++) {
		int row = rows_ - 2 - keylines_ + 1 + i;
		s += "\x1b[7m";
		put_fill(s, row, keyline_cache_[i], cols_);
		s += "\x1b[0m";
	}
}

void UI::draw_msg(std::string &s)
{
	std::string t = sanitize_ctrl(status_);
	if (t != msg_shown_) {          /* new message: restart the marquee */
		msg_scroll_ = 0;
		msg_shown_ = t;
	}
	if (u8width(t) > cols_)
		t = cyclic_window(t, msg_scroll_, cols_);
	put_fill(s, msg_row_, t, cols_);
}

void UI::draw_input(std::string &s)
{
	if (mode_ != PROMPT && mode_ != CONFIRM && mode_ != CAPTCHA) {
		put(s, input_row_, 1, "\x1b[K");
		return;
	}
	const std::string &label = prompt_label_;
	put(s, input_row_, 1, "\x1b[K");
	put(s, input_row_, 1, label);
	int labw = u8width(label);
	int y = cols_ - labw;          /* screen columns available to the input */
	if (y < 1) y = 1;
	int x = u8width(prompt_buf_);  /* total display width of the input */
	int n = (x < y / 4) ? x : y / 4;   /* min width that must stay visible */
	if (n < 1) n = 1;
	/* display window = available width minus one column, which is reserved so
	 * the cursor can sit after all the characters */
	int textw = y - 1;
	if (textw < 1) textw = 1;
	int showw = (x < textw) ? x : textw;
	if (showw < n) showw = n;
	if (showw < 1) showw = 1;
	/* follow the cursor: pull the window right if the cursor is left of it,
	 * push it left only when the cursor would leave the terminal on the right */
	int curw = u8width(prompt_buf_.substr(0, prompt_cx_));
	if (curw < prompt_scroll_) prompt_scroll_ = curw;
	if (curw - prompt_scroll_ > showw) prompt_scroll_ = curw - showw;
	/* clip the left side too: keep the cursor at least n columns into the
	 * window when x > n, by shifting the window right.  Only the cursor's
	 * screen column moves, not the character it is on. */
	if (x > n && curw - prompt_scroll_ < n) prompt_scroll_ = curw - n;
	if (prompt_scroll_ < 0) prompt_scroll_ = 0;
	/* snap the scroll offset UP to a cluster boundary so the window starts on
	 * a whole cluster and its width never exceeds showw (so the last wide
	 * cluster is never dropped). */
	{
		int acc = 0, snap = 0;
		for (size_t i = 0; i < prompt_buf_.size();) {
			if (acc >= prompt_scroll_) { snap = acc; break; }
			size_t j = next_cluster(prompt_buf_, i);
			acc += cluster_width(prompt_buf_, i, j);
			snap = acc;
			i = j;
		}
		prompt_scroll_ = snap;
	}
	/* build the visible substring starting at display column prompt_scroll_
	 * and compute the cursor's column inside it (cluster safe) */
	std::string shown;
	int curcol = 0;
	{
		int cw = 0;
		for (size_t i = 0; i < prompt_buf_.size();) {
			size_t j = next_cluster(prompt_buf_, i);
			int w = cluster_width(prompt_buf_, i, j);
			if (cw + w <= prompt_scroll_) { cw += w; i = j; continue; }
			int disp = cw - prompt_scroll_;
			if (disp + w > showw) break;   /* a wide cluster that won't fit: drop */
			if ((int)i < (int)prompt_cx_) curcol = disp + w;
			shown.append(prompt_buf_, i, j - i);
			cw += w;
			i = j;
		}
	}
	prompt_curcol_ = curcol;
	put(s, input_row_, 1 + labw, shown.c_str());
}

/* client rendering calibration, measured via cursor-position reports:
 *   write "<cluster> ESC[6n" -> the terminal answers "ESC[row;colR"
 *   -> col-1 is the width the CLIENT actually rendered the cluster with.
 * Different terminals disagree (PuTTY explodes ZWJ sequences, Windows
 * Terminal composes them), so we ask once at login. */

/* ask the client how wide it renders one probe cluster; <0 = no answer */
/* read one cursor-position report (ESC[row;colR); returns col, -1 on none */
static int read_cpr(ssh_channel ch, int timeout_ms)
{
	std::string reply;
	char b[64];
	int waited = 0;
	while (waited < timeout_ms) {
		int n = ssh_channel_read_timeout(ch, b, sizeof(b), 0, 20);
		if (n > 0) {
			reply.append(b, (size_t)n);
			size_t p = reply.find('R');
			if (p != std::string::npos) {
				int r = 0, c = 0;
				if (sscanf(reply.c_str(), "\x1b[%d;%dR", &r, &c) == 2)
					return c;
				return -1;
			}
			continue;
		}
		waited += 20;
	}
	return -1;
}

/* ask the client how wide it renders one probe cluster; <0 = no answer.
 * The cursor column is measured before and after, so the result does not
 * depend on where the cursor happened to be. */
static int probe_cluster_width(ssh_channel ch, const std::string &cluster)
{
	std::string q = "\r\x1b[6n";
	ssh_channel_write(ch, q.data(), (uint32_t)q.size());
	int base = read_cpr(ch, 400);
	if (base < 0)
		return -1;
	std::string out = cluster + "\x1b[6n";
	ssh_channel_write(ch, out.data(), (uint32_t)out.size());
	int after = read_cpr(ch, 400);
	if (after < 0)
		return -1;
	return after - base;
}

static void calibrate_client(ssh_channel ch, ssh_session session, int rows)
{
	/* blocking reads so the cursor-position replies can actually arrive */
	ssh_set_blocking(session, 1);
	/* VS16 presentation: 2 when honoured, 1 when the client ignores it */
	int w = probe_cluster_width(ch, "\xE2\x98\xBA\xEF\xB8\x8F");
	if (w == 1)
		g_w_vs16 = 1;
	/* ZWJ chain: 2 when composed, more when exploded into parts */
	w = probe_cluster_width(ch,
	        "\xF0\x9F\x91\xA8\xE2\x80\x8D\xF0\x9F\x91\xA9"
	        "\xE2\x80\x8D\xF0\x9F\x91\xA6");
	if (w > 2)
		g_zwj_composed = false;
	ssh_set_blocking(session, 0);
	/* clean up the probe line and hide any leftovers */
	std::string clr = sfmt("\x1b[%d;1H\x1b[2K", rows);
	ssh_channel_write(ch, clr.data(), (uint32_t)clr.size());
}


static void channel_write_all(ssh_channel ch, const std::string &s)
{
	size_t off = 0;
	int stall = 0;
	while (off < s.size()) {
		int n = ssh_channel_write(ch, s.data() + off,
		                          (uint32_t)(s.size() - off));
		if (n > 0) {
			off += (size_t)n;
			stall = 0;
			continue;
		}
		if (n == SSH_AGAIN) {
			if (++stall > 5000)   /* ~5s without progress: give up */
				return;
			usleep(1000);
			continue;
		}
		return;                   /* error: the channel is gone */
	}
}

void UI::render()
{
	layout();
	/* keep the directory registry current (used by the "ol here/all");
	 * a directory change moves us between "here" groups, so broadcast it.
	 * While the captcha is up we are not in any directory yet. */
	if (mode_ != CAPTCHA) {
		std::lock_guard<std::mutex> lk(g_sess_mtx);
		auto it = g_sessions.find(sid_);
		if (it == g_sessions.end() || it->second != cwd_) {
			g_sessions[sid_] = cwd_;
			g_online_epoch++;
		}
	}
	std::string s;
	if (cols_ != last_cols_ || rows_ != last_rows_) {
		s += "\x1b[2J";
		last_cols_ = cols_;
		last_rows_ = rows_;
	}
	s += "\x1b[?25l";
	Mode cv = content_view();
	if (mode_ == CAPTCHA)
		draw_captcha(s);
	else if (cv == EDITOR)
		draw_editor(s);
	else
		draw_list(s);
	draw_keys(s);
	draw_msg(s);
	draw_input(s);
	/* place cursor */
	if (mode_ == PROMPT || mode_ == CONFIRM || mode_ == CAPTCHA) {
		int labw = u8width(prompt_label_);
		int col = 1 + labw + prompt_curcol_;
		if (col < 1 + labw) col = 1 + labw;
		if (col > cols_) col = cols_;
		s += sfmt("\x1b[%d;%dH\x1b[?25h", input_row_, col);
	} else if (cv == EDITOR) {
		int numw = 1;
		{
			int n = editor_line_count();
			int d = 0;
			while (n > 0) { d++; n /= 10; }
			numw = std::max(3, d) + 1;
		}
		int w = main_cols_ - numw - 1;   /* reserve one column for the cursor */
		if (w < 1) w = 1;
		int cdisp = 0;
		for (int li = 0; li < cy_; li++)
			cdisp += (int)u8wrap(sanitize_ctrl(lines_[li]), w).size();
		int chunk = 0, col = 0;
		cursor_chunk(sanitize_ctrl(lines_[cy_]), cx_, w, chunk, col);
		cdisp += chunk;
		int ccol = numw + col;
		if (ccol < 0) ccol = 0;
		if (ccol > main_cols_ - 1) ccol = main_cols_ - 1;
		int crow = main_top_ + (cdisp - etop_);
		if (crow < main_top_) crow = main_top_;
		if (crow > main_bottom_) crow = main_bottom_;
		s += sfmt("\x1b[%d;%dH\x1b[?25h", crow, ccol + 1);
	} else {
		s += "\x1b[?25l";
	}
	channel_write_all(ch_, s);
}

/* ---- input ---- */

bool UI::poll_resize()
{
	bool changed = false;
	/* libssh delivers window-change as a channel request message */
	ssh_message m;
	while ((m = ssh_message_get(session_)) != nullptr) {
		int type = ssh_message_type(m);
		int sub = ssh_message_subtype(m);
		if (type == SSH_REQUEST_CHANNEL &&
		    sub == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
			int c = ssh_message_channel_request_pty_width(m);
			int r = ssh_message_channel_request_pty_height(m);
			if (c > 0 && c != cols_) { cols_ = c; changed = true; }
			if (r > 0 && r != rows_) { rows_ = r; changed = true; }
			ssh_message_channel_request_reply_success(m);
		} else {
			ssh_message_reply_default(m);
		}
		ssh_message_free(m);
	}
	return changed;
}

bool UI::next_key(KeyEvent &ev)
{
	bool resized = false, tick = false, updated = false;
	time_t last_ka = 0;
	auto fill = [&](size_t need) -> bool {
		while (inbuf_.size() < need) {
			char b[64];
			int n = ssh_channel_read_timeout(ch_, b, sizeof(b), 0, 100);
			if (n > 0) { inbuf_.append(b, (size_t)n); continue; }
			if (n == SSH_AGAIN) {
				if (poll_resize()) resized = true;
			} else {
				/* SSH_ERROR / EOF / closed channel / dead session: the
				 * connection is gone (this is what an RST looks like) */
				if (n < 0 || !ssh_is_connected(session_) ||
				    ssh_channel_is_eof(ch_) || !ssh_channel_is_open(ch_))
					return false;
				if (poll_resize()) resized = true;
			}
			/* heartbeat: probe the client once per second so a dead link
			 * is noticed quickly and editor locks get released */
			time_t now = time(nullptr);
			if (now != last_ka) {
				last_ka = now;
				if (ssh_send_keepalive(session_) != SSH_OK ||
				    !ssh_channel_is_open(ch_))
					return false;
			}
			if (resized)
				return true;
			if (mode_ == CAPTCHA) { tick = true; return true; }  /* countdown */
			if (marquee_active()) { tick = true; return true; }
			/* someone else changed the sandbox: push a redraw proactively */
			if (inbuf_.empty() && get_version() != seen_version_) {
				updated = true;
				return true;
			}
			/* the online count changed: broadcast a title-bar redraw */
			if (inbuf_.empty() &&
			    g_online_epoch.load(std::memory_order_relaxed) != seen_online_) {
				seen_online_ = g_online_epoch.load(std::memory_order_relaxed);
				return true;
			}
			/* an editor lock was taken or released somewhere: repaint */
			if (inbuf_.empty() &&
			    g_lock_epoch.load(std::memory_order_relaxed) != seen_lock_) {
				seen_lock_ = g_lock_epoch.load(std::memory_order_relaxed);
				return true;
			}
			/* a bell was sent: wake up so process_bells() can ring */
			if (inbuf_.empty() &&
			    g_bell_seq.load(std::memory_order_relaxed) != seen_bell_id_)
				return true;
			/* a path event arrived: wake up for process_events() */
			if (inbuf_.empty() &&
			    g_ev_seq.load(std::memory_order_relaxed) != seen_event_id_)
				return true;
			/* a broadcast message arrived: repaint the message bar */
			if (inbuf_.empty() &&
			    g_msg_seq.load(std::memory_order_relaxed) != seen_msg_id_)
				return true;
		}
		return true;
	};

	if (!fill(1)) return false;
	if (resized && inbuf_.empty()) { ev.key = Key::Resize; return true; }
	if (tick && inbuf_.empty()) { ev.key = Key::Tick; return true; }
	if (updated && inbuf_.empty()) { ev.key = Key::Update; return true; }
	if (inbuf_.empty()) { ev.key = Key::Redraw; return true; }
	unsigned char c = (unsigned char)inbuf_[0];
	if (c == 0x1b) {
		char b2[8];
		int m = ssh_channel_read_timeout(ch_, b2, sizeof(b2), 0, 30);
		if (m > 0) inbuf_.append(b2, (size_t)m);
		/* an escape sequence arrives as one burst; if it looks incomplete
		 * (e.g. only "ESC [" so far), keep waiting briefly so a split
		 * sequence is not mistaken for a plain Esc */
		for (int wait = 0; wait < 8; wait++) {
			if (inbuf_.size() >= 2 && inbuf_[1] == '[') {
				if (inbuf_.size() == 2)
					goto more;                       /* params not arrived */
				{
					size_t k = 2;
					while (k < inbuf_.size() &&
					       ((inbuf_[k] >= '0' && inbuf_[k] <= '9') ||
					        inbuf_[k] == ';'))
						k++;
					if (k == inbuf_.size() && inbuf_[2] != 'A' &&
					    inbuf_[2] != 'B' && inbuf_[2] != 'C' &&
					    inbuf_[2] != 'D' && inbuf_[2] != 'H' &&
					    inbuf_[2] != 'F')
						goto more;                   /* final byte missing */
				}
			} else if (inbuf_.size() >= 2 && inbuf_[1] == 'O') {
				if (inbuf_.size() == 2)
					goto more;
			}
			break;
		more:
			m = ssh_channel_read_timeout(ch_, b2, sizeof(b2), 0, 30);
			if (m <= 0)
				break;                       /* nothing more coming */
			inbuf_.append(b2, (size_t)m);
		}
		if (inbuf_.size() >= 3 && inbuf_[1] == '[') {
			/* CSI: optional parameters, then a final byte */
			size_t k = 2;
			while (k < inbuf_.size() &&
			       ((inbuf_[k] >= '0' && inbuf_[k] <= '9') || inbuf_[k] == ';'))
				k++;
			if (k < inbuf_.size()) {
				int fin = inbuf_[k];
				int param = 0;
				for (size_t q = 2; q < k; q++)
					if (inbuf_[q] >= '0' && inbuf_[q] <= '9')
						param = param * 10 + (inbuf_[q] - '0');
				size_t eat = k + 1;
				Key kk = Key::None;
				switch (fin) {
				case 'A': kk = Key::Up; break;
				case 'B': kk = Key::Down; break;
				case 'C': kk = Key::Right; break;
				case 'D': kk = Key::Left; break;
				case 'H': kk = Key::Home; break;
				case 'F': kk = Key::End; break;
				case '~':
					switch (param) {
					case 1: case 7: kk = Key::Home; break;
					case 3: kk = Key::Delete; break;
					case 4: case 8: kk = Key::End; break;
					case 5: kk = Key::PageUp; break;
					case 6: kk = Key::PageDown; break;
					default: break;   /* Insert/F-keys/...: swallow */
					}
					break;
				default: break;       /* unknown CSI: swallow the sequence */
				}
				inbuf_.erase(0, eat);
				if (kk != Key::None) { ev.key = kk; return true; }
				return true;          /* recognized but unmapped: no event */
			}
			/* incomplete sequence: fall through and treat the ESC alone */
		} else if (inbuf_.size() >= 3 && inbuf_[1] == 'O') {
			/* SS3: application-mode arrows / Home / End / F1-F4 */
			Key kk = Key::None;
			switch (inbuf_[2]) {
			case 'A': kk = Key::Up; break;
			case 'B': kk = Key::Down; break;
			case 'C': kk = Key::Right; break;
			case 'D': kk = Key::Left; break;
			case 'H': kk = Key::Home; break;
			case 'F': kk = Key::End; break;
			default: break;           /* F1-F4 etc.: swallow */
			}
			inbuf_.erase(0, 3);
			if (kk != Key::None) { ev.key = kk; return true; }
			return true;
		}
		inbuf_.erase(0, 1);
		ev.key = Key::Esc;
		return true;
	}
	if (c == 0x02) { inbuf_.erase(0, 1); ev.key = Key::CtrlB; return true; }
	if (c == 0x03) { inbuf_.erase(0, 1); ev.key = Key::CtrlC; return true; }
	if (c == 0x13) { inbuf_.erase(0, 1); ev.key = Key::CtrlS; return true; }
	if (c == 0x07) { inbuf_.erase(0, 1); ev.key = Key::CtrlG; return true; }
	if (c == 0x0c) { inbuf_.erase(0, 1); ev.key = Key::CtrlL; return true; }
	if (c == 0x04) { inbuf_.erase(0, 1); ev.key = Key::CtrlD; return true; }
	if (c == 0x7f || c == 0x08) { inbuf_.erase(0, 1); ev.key = Key::Backspace; return true; }
	if (c == 0x0d || c == 0x0a) { inbuf_.erase(0, 1); ev.key = Key::Enter; return true; }
	if (c == 0x09) { inbuf_.erase(0, 1); ev.key = Key::Tab; return true; }
	int sl = u8seqlen(c);
	if (!fill((size_t)sl)) return false;
	ev.key = Key::Char;
	ev.text = inbuf_.substr(0, (size_t)sl);
	inbuf_.erase(0, (size_t)sl);
	return true;
}

/* ---- prompt / confirm ---- */

void UI::open_prompt(int action, const std::string &label, const std::string &prefill)
{
	base_ = content_view();
	mode_ = PROMPT;
	prompt_action_ = action;
	prompt_label_ = label;
	prompt_buf_ = prefill;
	prompt_cx_ = prompt_buf_.size();
	prompt_scroll_ = 0;
}

void UI::open_confirm(int action, const std::string &what)
{
	base_ = content_view();
	mode_ = CONFIRM;
	confirm_action_ = action;
	confirm_what_ = what;
	prompt_label_ = "type 'del' to confirm: ";
	status_ = "delete " + what + " ?";
	prompt_buf_.clear();
	prompt_cx_ = 0;
	prompt_scroll_ = 0;
}

void UI::do_prompt_commit()
{
	std::string val = prompt_buf_;
	int action = prompt_action_;
	prompt_buf_.clear();
	prompt_cx_ = prompt_scroll_ = 0;
	if (action == 6) {
		/* editor discard confirmation: only the word "esc" discards */
		if (val == "esc") leave_editor();
		else { status_ = "discard cancelled"; mode_ = EDITOR; }
		return;
	}
	mode_ = LIST;
	if (val.empty()) return;

	auto target = [&](const std::string &name, std::string &rel) {
		return sb_.normalize(cwd_, name, rel);
	};
	switch (action) {
	case 1: {
		std::string rel;
		if (!Sandbox::valid_name(val) || !target(val, rel)) { status_ = "invalid name"; return; }
		status_ = sb_.create_file(rel, ip_, false) ? "created " + val : "create failed";
		if (status_.rfind("created", 0) == 0) {
			after_change();
			/* the cursor jumps to the freshly created entry */
			for (int i = 0; i < (int)entries_.size(); i++)
				if (entries_[i].name == val) { sel_ = i; break; }
			ensure_sel_visible();
		}
		break;
	}
	case 2: {
		std::string rel;
		if (!Sandbox::valid_name(val) || !target(val, rel)) { status_ = "invalid name"; return; }
		status_ = sb_.create_file(rel, ip_, true) ? "mkdir " + val : "mkdir failed";
		if (status_.rfind("mkdir", 0) == 0) {
			after_change();
			/* the cursor jumps to the freshly created folder */
			for (int i = 0; i < (int)entries_.size(); i++)
				if (entries_[i].name == val) { sel_ = i; break; }
			ensure_sel_visible();
		}
		break;
	}
	case 3: {
		if (entries_.empty()) return;
		if (!Sandbox::valid_name(val)) { status_ = "invalid name"; return; }
		std::string from = cwd_.empty() ? entries_[sel_].name : cwd_ + "/" + entries_[sel_].name, to;
		if (!sb_.normalize(cwd_, val, to)) { status_ = "invalid name"; return; }
		status_ = sb_.rename_entry(from, to, ip_) ? "renamed" : "rename failed";
		if (status_ == "renamed") after_change();
		break;
	}
	case 4: {
		if (entries_.empty()) return;
		std::string from = cwd_.empty() ? entries_[sel_].name : cwd_ + "/" + entries_[sel_].name, to;
		if (!sb_.normalize(cwd_, val, to)) { status_ = "invalid target"; return; }
		if (to == from) { status_ = "same path"; return; }
		status_ = sb_.rename_entry(from, to, ip_) ? "moved" : "move failed";
		if (status_ == "moved") after_change();
		break;
	}
	case 7: {
		/* goto a path.  A trailing slash means "enter the directory":
		 *   goto a/  -> if a is a directory, open it
		 *            -> if a is a file, report that it is not a directory
		 *   goto a   -> open a's parent and select a (any type) */
		bool trail = (!val.empty() && val.back() == '/');
		std::string rel;
		if (!sb_.normalize(cwd_, val, rel)) {
			status_ = "path is outside the root";
			return;
		}
		if (rel.empty()) {          /* the root itself */
			if (!trail) {
				/* there is nothing above the root to open and select */
				status_ = "can't select the root. please goto the /";
				return;
			}
			if (cwd_.empty()) {     /* already at the root */
				status_ = "same directory and no action";
				return;
			}
			cwd_.clear();
			entries_.clear();
			refresh();
			sel_ = top_ = 0;
			status_ = "goto /";
			return;
		}
		if (!sb_.exists(rel)) {
			status_ = "not found: " + val;
			return;
		}
		if (trail) {
			if (!sb_.is_dir(rel)) {
				status_ = "exists but is not a directory";
				return;
			}
			if (cwd_ == rel) {      /* already here */
				status_ = "same directory and no action";
				return;
			}
			cwd_ = rel;             /* enter the directory itself */
			entries_.clear();
			refresh();
			sel_ = top_ = 0;
			status_ = "goto " + rel + "/";
			return;
		}
		/* no trailing slash: open the parent and select the entry */
		size_t p = rel.rfind('/');
		std::string parent = (p == std::string::npos) ? std::string() : rel.substr(0, p);
		std::string base = rel.substr(p + 1);
		if (parent != cwd_) {       /* different directory: fresh load */
			cwd_ = parent;
			entries_.clear();
			refresh();
			sel_ = top_ = 0;
		}
		/* same directory: keep the list and its order, just select */
		for (int i = 0; i < (int)entries_.size(); i++)
			if (entries_[i].name == base) { sel_ = i; break; }
		ensure_sel_visible();
		status_ = "goto " + rel;
		return;
	}
	case 8: {
		/* broadcast the typed message to every session */
		push_message(ip_, val);
		status_ = "broadcast sent";
		break;
	}
	case 5: {
		int ln = atoi(val.c_str());
		if (ln < 1) ln = 1;
		if (ln > editor_line_count()) ln = editor_line_count();
		cy_ = ln - 1;
		cx_ = 0;
		mode_ = EDITOR;
		break;
	}
	}
	refresh();
}

void UI::handle_confirm(const KeyEvent &ev)
{
	switch (ev.key) {
	case Key::Enter:
		if (prompt_buf_ == "del") {
			std::string rel = confirm_what_;
			int rc = sb_.remove_entry(rel, ip_);
			status_ = (rc == 1) ? "deleted"
			         : (rc == -2) ? "file is being edited by someone else"
			         : (rc < 0) ? "deleted (locked entries kept)"
			                    : "delete failed";
			mode_ = LIST;
			if (rc == 1 || rc == -1) after_change();
		} else {
			status_ = "not deleted";
			mode_ = LIST;
		}
		prompt_buf_.clear();
		prompt_cx_ = 0;
		break;
	case Key::Esc: mode_ = LIST; break;
	case Key::Backspace:
		if (prompt_cx_ > 0) {
			size_t k = prev_cluster(prompt_buf_, prompt_cx_);
			prompt_buf_.erase(k, prompt_cx_ - k);
			prompt_cx_ = k;
		}
		break;
	case Key::Left:
		if (prompt_cx_ > 0)
			prompt_cx_ = prev_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Right:
		if (prompt_cx_ < prompt_buf_.size())
			prompt_cx_ = next_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Char: prompt_buf_.insert(prompt_cx_, ev.text); prompt_cx_ += ev.text.size(); break;
	default: break;
	}
}

/* ---- list handling ---- */

void UI::handle_list(const KeyEvent &ev)
{
	name_scroll_ = 0;
	switch (ev.key) {
	case Key::Up: if (sel_ > 0) sel_--; break;
	case Key::Down: if (sel_ + 1 < (int)entries_.size()) sel_++; break;
	case Key::Left:            /* first entry of the whole list */
		if (!entries_.empty()) { sel_ = 0; ensure_sel_visible(); }
		break;
	case Key::Right:           /* last entry of the whole list */
		if (!entries_.empty()) {
			sel_ = (int)entries_.size() - 1;
			ensure_sel_visible();
		}
		break;
	case Key::PageUp:
	case Key::PageDown: {
		/* page by the viewport: remember the selected entry's row E inside
		 * the viewport, scroll exactly one page, then select the entry that
		 * lands on row E (clipped if the list is too short) */
		if (entries_.empty())
			break;
		layout();
		std::vector<std::vector<int>> el;
		entry_lines(el);
		int hgt = (int)el.size();
		int mainh = main_bottom_ - main_top_ + 1;
		if (mainh < 1) mainh = 1;
		int vis = mainh / hgt;
		if (vis < 1) vis = 1;
		int relrow = sel_ - top_;
		int total = (int)entries_.size();
		if (ev.key == Key::PageUp)
			top_ -= vis;
		else
			top_ += vis;
		/* clip so the viewport stays completely full (no empty rows) */
		if (total <= vis)
			top_ = 0;
		else if (top_ > total - vis)
			top_ = total - vis;
		if (top_ < 0)
			top_ = 0;
		/* then select the entry that lands on row E */
		sel_ = top_ + relrow;
		if (sel_ > total - 1) sel_ = total - 1;
		if (sel_ < 0) sel_ = 0;
		break;
	}
	case Key::Home: sel_ = 0; break;
	case Key::End: sel_ = (int)entries_.size() - 1; break;
	case Key::CtrlB: push_bell(1, ""); break;   /* bell: everyone */
	case Key::Enter: {
		if (entries_.empty()) break;
		const Entry &e = entries_[sel_];
		if (e.isdir) {
			cwd_ = cwd_.empty() ? e.name : cwd_ + "/" + e.name;
			sel_ = top_ = 0;
			refresh(false);
		} else {
			edit_rel_ = cwd_.empty() ? e.name : cwd_ + "/" + e.name;
			if (!filelock_acquire(edit_rel_)) {
				status_ = "file is being edited by someone else";
			} else {
				edit_lock_ = edit_rel_;
				editor_load(edit_rel_);
				mode_ = EDITOR;
			}
		}
		break;
	}
	case Key::Char:
		if (ev.text == "n") open_prompt(1, "new file: ", "");
		else if (ev.text == "N") open_prompt(2, "new dir: ", "");
		else if (ev.text == "m") { if (!entries_.empty()) open_prompt(4, "move to: ", ""); }
	else if (ev.text == "g") open_prompt(7, "goto: ", "");
	else if (ev.text == "b") push_bell(0, cwd_);   /* bell: this directory */
	else if (ev.text == "B") open_prompt(8, "broadcast: ", "");
		else if (ev.text == "d") {
			if (!entries_.empty()) {
				std::string rel = cwd_.empty() ? entries_[sel_].name : cwd_ + "/" + entries_[sel_].name;
				open_confirm(0, rel);
			}
		} else if (ev.text == "t") { sort_mode_ = 1; resort(); }
		else if (ev.text == "s") { sort_mode_ = 0; resort(); }
		else if (ev.text == "r") { refresh(); }
		else if (ev.text == "q") {
			throw 1;
		}
		break;
	case Key::Esc:
		if (!cwd_.empty()) {
			size_t s = cwd_.rfind('/');
			cwd_ = (s == std::string::npos) ? "" : cwd_.substr(0, s);
			sel_ = top_ = 0;
			refresh(false);
		}
		break;
	default: break;
	}
}

/* ---- editor ---- */

void UI::editor_load(const std::string &rel)
{
	std::string data = sb_.read_content(rel);
	lines_.clear();
	size_t pos = 0;
	while (pos <= data.size()) {
		size_t e = data.find('\n', pos);
		if (e == std::string::npos) { lines_.push_back(data.substr(pos)); break; }
		lines_.push_back(data.substr(pos, e - pos));
		pos = e + 1;
	}
	if (lines_.empty()) lines_.push_back("");
	cy_ = cx_ = etop_ = 0;
	dirty_ = false;
	status_.clear();
}

void UI::editor_save()
{
	std::string data;
	for (size_t i = 0; i < lines_.size(); i++) {
		data += lines_[i];
		if (i + 1 < lines_.size()) data += "\n";
	}
	status_ = sb_.save_content(edit_rel_, data, ip_) ? "saved" : "save failed";
	if (status_ == "saved") { dirty_ = false; bump_version(); }
}

void UI::leave_editor()
{
	if (!edit_lock_.empty()) {
		filelock_release(edit_lock_);
		edit_lock_.clear();
	}
	mode_ = LIST;
	refresh();
}

/* remember the cursor's column for the next vertical move (so the cursor
 * can travel up/down between the reserved end-of-visual-line positions) */
void UI::editor_remember_goal()
{
	int numw = 1;
	{
		int n = editor_line_count();
		int d = 0;
		while (n > 0) { d++; n /= 10; }
		numw = std::max(3, d) + 1;
	}
	int w = main_cols_ - numw - 1;
	if (w < 1) w = 1;
	int chunk = 0, col = 0;
	cursor_chunk(sanitize_ctrl(lines_[cy_]), cx_, w, chunk, col);
	goal_col_ = col;
}

void UI::handle_editor(const KeyEvent &ev)
{
	switch (ev.key) {
	case Key::Up:
	case Key::Down:
	case Key::PageUp:
	case Key::PageDown: {
		/* all movement is by VISUAL lines: soft-wrapped chunks count */
		int numw = 1;
		{
			int n = editor_line_count();
			int dgt = 0;
			while (n > 0) { dgt++; n /= 10; }
			numw = std::max(3, dgt) + 1;
		}
		int w = main_cols_ - numw - 1;
		if (w < 1) w = 1;
		layout();
		int mainh = main_bottom_ - main_top_ + 1;
		if (mainh < 1) mainh = 1;
		bool page = (ev.key == Key::PageUp || ev.key == Key::PageDown);
		int etop_old = etop_;
		/* current visual row of the cursor + its column */
		int d = 0;
		for (int li = 0; li < cy_; li++)
			d += (int)u8wrap(sanitize_ctrl(lines_[li]), w).size();
		int chunk = 0, col = 0;
		cursor_chunk(sanitize_ctrl(lines_[cy_]), cx_, w, chunk, col);
		d += chunk;
		if (goal_col_ >= 0)
			col = goal_col_;   /* vertical moves reuse the remembered column */
		int nd;
		if (page) {
			/* phase 1: scroll the viewport a full page; the cursor has
			 * nothing to do with this */
			int total = 0;
			for (int li = 0; li < editor_line_count(); li++)
				total += (int)u8wrap(sanitize_ctrl(lines_[li]), w).size();
			if (ev.key == Key::PageUp)
				etop_ -= mainh;
			else
				etop_ += mainh;
			if (total <= mainh)
				etop_ = 0;
			else if (etop_ > total - mainh)
				etop_ = total - mainh;
			if (etop_ < 0)
				etop_ = 0;
			/* phase 2: put the cursor back on its old screen row; this
			 * never moves the offset, so clamp the row into the viewport
			 * first */
			int screen_row = std::min(std::max(d - etop_old, 0), mainh - 1);
			nd = etop_ + screen_row;
			if (nd > total - 1) nd = total - 1;
			if (nd < 0) nd = 0;
		} else {
			nd = (ev.key == Key::Up) ? d - 1 : d + 1;
			if (nd < 0) { cy_ = 0; cx_ = 0; break; }
		}
		/* locate the logical line / chunk of visual row nd */
		int total2 = 0, tl = -1, tc = 0;
		for (int li = 0; li < editor_line_count(); li++) {
			int nch = (int)u8wrap(sanitize_ctrl(lines_[li]), w).size();
			if (nd < total2 + nch) { tl = li; tc = nd - total2; break; }
			total2 += nch;
		}
		if (tl < 0) {   /* past the end: end of the last line */
			cy_ = editor_line_count() - 1;
			cx_ = (int)lines_[cy_].size();
			break;
		}
		cy_ = tl;
		cx_ = (int)chunk_byte_offset(sanitize_ctrl(lines_[cy_]), tc, col, w);
		break;
	}
	case Key::Left:
		if (cx_ > 0) cx_ = (int)prev_cluster(lines_[cy_], (size_t)cx_);
		else if (cy_ > 0) { cy_--; cx_ = (int)lines_[cy_].size(); }
		editor_remember_goal();
		break;
	case Key::Right:
		if (cx_ < (int)lines_[cy_].size()) cx_ = (int)next_cluster(lines_[cy_], (size_t)cx_);
		else if (cy_ + 1 < editor_line_count()) { cy_++; cx_ = 0; }
		editor_remember_goal();
		break;
	case Key::Home: cx_ = 0; editor_remember_goal(); break;
	case Key::End: cx_ = (int)lines_[cy_].size(); editor_remember_goal(); break;
	case Key::Backspace:
		if (cx_ > 0) {
			int k = (int)prev_cluster(lines_[cy_], (size_t)cx_);
			lines_[cy_].erase(k, cx_ - k);
			cx_ = k;
			dirty_ = true;
		} else if (cy_ > 0) {
			int prevlen = (int)lines_[cy_ - 1].size();
			lines_[cy_ - 1] += lines_[cy_];
			lines_.erase(lines_.begin() + cy_);
			cy_--;
			cx_ = prevlen;
			dirty_ = true;
		}
		break;
	case Key::Delete:
		if (cx_ < (int)lines_[cy_].size()) {
			int k = (int)next_cluster(lines_[cy_], (size_t)cx_);
			lines_[cy_].erase(cx_, k - cx_);
			dirty_ = true;
		} else if (cy_ + 1 < editor_line_count()) {
			lines_[cy_] += lines_[cy_ + 1];
			lines_.erase(lines_.begin() + cy_ + 1);
			dirty_ = true;
		}
		break;
	case Key::Enter: {
		std::string rest = lines_[cy_].substr(cx_);
		lines_[cy_].erase(cx_);
		lines_.insert(lines_.begin() + cy_ + 1, rest);
		cy_++; cx_ = 0;
		dirty_ = true;
		break;
	}
	case Key::Char:
		lines_[cy_].insert(cx_, ev.text);
		goal_col_ = -1;
		cx_ += (int)ev.text.size();
		dirty_ = true;
		break;
	case Key::CtrlS: editor_save(); break;
	case Key::CtrlG: open_prompt(5, "goto line: ", ""); break;
	case Key::Esc: case Key::CtrlC:
		if (dirty_) open_prompt(6, "type 'esc' to discard changes: ", "");
		else leave_editor();
		break;
	default: break;
	}
}

/* ---- login captcha ---- */

void UI::captcha_new_code()
{
	static const char *al = "bcdefhjkmnpqrstuvwxyz23467";
	unsigned s = (unsigned)time(nullptr) ^ (unsigned)(uintptr_t)this
	           ^ (unsigned)rand();
	int an = (int)strlen(al);
	captcha_code_.clear();
	for (int i = 0; i < 4; i++)
		captcha_code_ += al[(int)(art_rand(s) * an) % an];
}

void UI::captcha_regen(int w, int h)
{
	unsigned seed = (unsigned)time(nullptr) * 2654435761u
	              ^ (unsigned)(uintptr_t)this ^ (unsigned)rand();
	if (captcha_weak_) {
		/* weak check: just the eight digits, centred, nothing else */
		std::vector<std::string> g(h, std::string(w, ' '));
		std::string disp;
		for (char c : captcha_code_) {
			disp += c;
			disp += ' ';
		}
		if (!disp.empty())
			disp.pop_back();
		int y0 = h / 2;
		int x0 = (w - (int)disp.size()) / 2;
		if (x0 < 0)
			x0 = 0;
		for (int k = 0; k < (int)disp.size() && x0 + k < w; k++)
			g[y0][x0 + k] = disp[k];
		captcha_screen_ = g;
		captcha_art_w_ = w;
		captcha_art_h_ = h;
		return;
	}
	captcha_art_ = make_captcha_art(captcha_code_, w, h, seed);
	captcha_art_w_ = w;
	captcha_art_h_ = h;

	/* the art is pasted at a random position; noise goes everywhere EXCEPT
	 * over the art so its strokes stay clean */
	int arth = (int)captcha_art_.size();
	int arw = 0;
	for (auto &l : captcha_art_)
		arw = std::max(arw, (int)l.size());

	/* the terminal is smaller than the art: ask for a bigger one instead of
	 * showing a clipped, unsolvable picture */
	if (captcha_art_.empty() || arw > w || arth > h) {
		std::vector<std::string> g(h, std::string(w, ' '));
		/* word-wrap the hint to the terminal width, then centre it */
		std::vector<std::string> lines;
		std::string text = "terminal too small - please use a larger terminal";
		std::string cur;
		size_t i2 = 0;
		while (i2 < text.size()) {
			size_t sp = text.find(' ', i2);
			if (sp == std::string::npos)
				sp = text.size();
			std::string word = text.substr(i2, sp - i2);
			i2 = sp + 1;
			while ((int)word.size() > w) {   /* hard-break a long word */
				if (!cur.empty()) { lines.push_back(cur); cur.clear(); }
				lines.push_back(word.substr(0, w));
				word = word.substr(w);
			}
			if (cur.empty())
				cur = word;
			else if ((int)(cur.size() + 1 + word.size()) <= w)
				cur += " " + word;
			else {
				lines.push_back(cur);
				cur = word;
			}
		}
		if (!cur.empty())
			lines.push_back(cur);
		int y0 = (h - (int)lines.size()) / 2;
		for (int k = 0; k < (int)lines.size(); k++) {
			int yy = y0 + k;
			if (yy < 0 || yy >= h)
				continue;
			int x0 = (w - (int)lines[k].size()) / 2;
			if (x0 < 0) x0 = 0;
			for (int c2 = 0; c2 < (int)lines[k].size() && x0 + c2 < w; c2++)
				g[yy][x0 + c2] = lines[k][c2];
		}
		captcha_screen_ = g;
		return;
	}
	int ox = 0, oy = 0;
	if (arw < w)
		ox = (int)(art_rand(seed) * (w - arw + 1));
	if (arth < h)
		oy = (int)(art_rand(seed) * (h - arth + 1));

	/* noise uses the SAME character set as the art, so it blends in */
	std::string charset;
	{
		bool seen[256] = {false};
		for (auto &l : captcha_art_)
			for (unsigned char ch2 : l)
				if (ch2 != ' ' && !seen[ch2]) {
					seen[ch2] = true;
					charset += (char)ch2;
				}
		if (charset.empty())
			charset = ".-+*#%@";
	}
	std::vector<std::string> g(h, std::string(w, ' '));
	int nn = (int)charset.size();
	for (int y = 0; y < h; y++)
		for (int x = 0; x < w; x++) {
			if (art_rand(seed) < 0.20f)
				g[y][x] = charset[(int)(art_rand(seed) * nn) % nn];
		}

	std::vector<unsigned char> artmask((size_t)w * h, 0);
	for (int y = 0; y < arth; y++) {
		int gy = oy + y;
		if (gy < 0 || gy >= h) continue;
		const std::string &line = captcha_art_[y];
		for (int x = 0; x < (int)line.size(); x++) {
			if (line[x] == ' ')
				continue;                       /* art is transparent */
			int gx = ox + x;
			if (gx >= 0 && gx < w) {
				g[gy][gx] = line[x];
				artmask[(size_t)gy * w + gx] = 1;   /* letters are protected */
			}
		}
	}
	/* zero-thickness noise lines (single-character wide) made of - | \ /
	 * which never overwrite the letters.  Their number and length scale
	 * with the screen size. */
	int nlines = std::max(1, w * h / 1400);
	int maxlen = (int)((w + h) * 0.5f);
	for (int li = 0; li < nlines; li++) {
		int x = (int)(art_rand(seed) * w);
		int y = (int)(art_rand(seed) * h);
		int dir = (int)(art_rand(seed) * 4);
		int len = 6 + (int)(art_rand(seed) * maxlen);
		int dx = 1, dy = 0;
		char lc = '-';
		switch (dir) {
		case 0: dx = 1; dy = 0; lc = '-'; break;
		case 1: dx = 0; dy = 1; lc = '|'; break;
		case 2: dx = 1; dy = 1; lc = '\\'; break;
		default: dx = 1; dy = -1; lc = '/'; break;
		}
		if (art_rand(seed) < 0.5f) {
			x = (int)(art_rand(seed) * w);
			y = 0;
		}
		for (int k = 0; k < len; k++) {
			int gx = x + dx * k, gy = y + dy * k;
			if (gx < 0 || gy < 0 || gx >= w || gy >= h)
				break;
			if (artmask[(size_t)gy * w + gx])
				continue;              /* never cover a letter */
			g[gy][gx] = lc;
		}
	}
	/* wandering noise lines: a random walk that turns by at most 90
	 * degrees every 6..11 cells (only a wall bounce may reverse it) */
	int nwander = std::max(1, w * h / 2000);
	for (int wi = 0; wi < nwander; wi++) {
		int x = (int)(art_rand(seed) * w);
		int y = (int)(art_rand(seed) * h);
		int steps = 10 + (int)(art_rand(seed) * (w + h));
		static const int ddx[8] = {1, 1, 0, -1, -1, -1, 0, 1};
		static const int ddy[8] = {0, -1, -1, -1, 0, 1, 1, 1};
		int di = (int)(art_rand(seed) * 8);
		int dx = ddx[di], dy = ddy[di];
		int run = 0, runlen = 6 + (int)(art_rand(seed) * 6);
		for (int k = 0; k < steps; k++) {
			if (run >= runlen) {
				static const int turn[4] = {-2, -1, 1, 2};
				di = (di + turn[(int)(art_rand(seed) * 4)] + 8) % 8;
				dx = ddx[di];
				dy = ddy[di];
				run = 0;
				runlen = 6 + (int)(art_rand(seed) * 6);
			}
			int gx = x + dx, gy = y + dy;
			if (gx < 0 || gy < 0 || gx >= w || gy >= h) {
				di = (di + 4) % 8;     /* bounce off the wall */
				dx = ddx[di];
				dy = ddy[di];
				gx = x + dx;
				gy = y + dy;
				if (gx < 0 || gy < 0 || gx >= w || gy >= h)
					break;
			}
			x = gx;
			y = gy;
			if (artmask[(size_t)y * w + x])
				continue;              /* never cover a letter */
			char c;
			if (dx == 0)
				c = '|';
			else if (dy == 0)
				c = '-';
			else
				c = (dx * dy > 0) ? '\\' : '/';
			g[y][x] = c;
			run++;
		}
	}
	captcha_screen_ = g;
}

void UI::draw_captcha(std::string &s)
{
	/* title bar carries the countdown */
	std::string tt = title_text();
	if (u8width(tt) > cols_)
		tt = cyclic_window(tt, title_scroll_, cols_);
	s += "\x1b[7m";
	put_fill(s, 1, tt, cols_);
	s += "\x1b[0m";
	int mainh = main_bottom_ - main_top_ + 1;
	if (mainh < 1) mainh = 1;
	if (captcha_screen_.empty() || captcha_art_w_ != main_cols_ ||
	    captcha_art_h_ != mainh)
		captcha_regen(main_cols_, mainh);   /* pty size changed */
	for (int i = 0; i < mainh; i++) {
		int row = main_top_ + i;
		if (i < (int)captcha_screen_.size())
			put_fill(s, row, captcha_screen_[i], main_cols_);
		else
			put(s, row, 1, "\x1b[K");
	}
}

void UI::handle_captcha(const KeyEvent &ev)
{
	switch (ev.key) {
	case Key::Esc:
		quit_ = true;               /* Esc disconnects outright */
		break;
	case Key::Enter: {
		std::string ans = prompt_buf_;
		for (auto &c : ans)
			if (c >= 'A' && c <= 'Z')
				c = (char)(c - 'A' + 'a');
		if (ans == captcha_code_) {
			status_ = "captcha passed";
			mode_ = LIST;
			entries_.clear();
			refresh();
		} else {
			status_ = "wrong, try again";
			prompt_buf_.clear();
			prompt_cx_ = 0;
			prompt_scroll_ = 0;
			if (!captcha_weak_)
				captcha_new_code();    /* a fresh puzzle each attempt */
			captcha_regen(main_cols_, main_bottom_ - main_top_ + 1);
		}
		break;
	}
	case Key::Backspace:
		if (prompt_cx_ > 0) {
			size_t k = prev_cluster(prompt_buf_, prompt_cx_);
			prompt_buf_.erase(k, prompt_cx_ - k);
			prompt_cx_ = k;
		}
		break;
	case Key::Left:
		if (prompt_cx_ > 0)
			prompt_cx_ = prev_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Right:
		if (prompt_cx_ < prompt_buf_.size())
			prompt_cx_ = next_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Char:
		prompt_buf_.insert(prompt_cx_, ev.text);
		prompt_cx_ += ev.text.size();
		break;
	default:
		break;
	}
}

void UI::handle_prompt(const KeyEvent &ev)
{
	switch (ev.key) {
	case Key::Enter: do_prompt_commit(); break;
	case Key::Esc:
		/* cancel: goto(5) and discard(6) return to the editor */
		if (prompt_action_ == 5 || prompt_action_ == 6) mode_ = EDITOR;
		else mode_ = LIST;
		break;
	case Key::Backspace:
		if (prompt_cx_ > 0) {
			size_t k = prev_cluster(prompt_buf_, prompt_cx_);
			prompt_buf_.erase(k, prompt_cx_ - k);
			prompt_cx_ = k;
		}
		break;
	case Key::Left:
		if (prompt_cx_ > 0)
			prompt_cx_ = prev_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Right:
		if (prompt_cx_ < prompt_buf_.size())
			prompt_cx_ = next_cluster(prompt_buf_, prompt_cx_);
		break;
	case Key::Char: prompt_buf_.insert(prompt_cx_, ev.text); prompt_cx_ += ev.text.size(); break;
	default: break;
	}
}

/* startup animation: the whole screen flashes between normal and reverse
 * video while a centred "sshfm" block always keeps the opposite video.
 * A terminal resize during the animation is picked up immediately. */
void UI::startup_flash()
{
	const char *word = "  sshfm  ";
	int wl = (int)strlen(word);
	for (int i = 0; i < 8; i++) {
		poll_resize();                 /* follow a resize while flashing */
		int cols = cols_, rows = rows_;
		int bx = (cols - wl) / 2;
		int by = rows / 2;
		if (bx < 1) bx = 1;
		if (by < 1) by = 1;
		std::string pad(cols > 0 ? cols : 1, ' ');
		std::string s = "\x1b[?25l\x1b[2J\x1b[H";
		bool screen_rev = (i % 2 == 0);
		s += screen_rev ? "\x1b[7m" : "\x1b[27m";
		for (int y = 1; y <= rows; y++)
			s += sfmt("\x1b[%d;1H%s", y, pad.c_str());
		s += screen_rev ? "\x1b[27m" : "\x1b[7m";
		s += sfmt("\x1b[%d;%dH%s", by, bx, word);
		s += "\x1b[0m";
		channel_write_all(ch_, s);
		usleep(90000);
	}
	channel_write_all(ch_, "\x1b[0m\x1b[2J\x1b[H\x1b[?25l");
}

void UI::run(ssh_channel ch, int cols, int rows)
{
	ch_ = ch;

	cols_ = cols > 10 ? cols : 80;
	rows_ = rows > 6 ? rows : 24;
	sid_ = ++g_next_sid;
	{
		std::lock_guard<std::mutex> lk(g_sess_mtx);
		/* a captcha session belongs to no directory yet */
		g_sessions[sid_] = (g_captcha_timeout > 0) ? std::string("\x01" "captcha")
		                                           : cwd_;
	}
	g_online_epoch++;   /* our "here" group gained a member */
	/* non-blocking so ssh_message_get() (resize polling) never stalls the
	 * key loop */
	ssh_set_blocking(session_, 0);
	/* ask the client how it actually renders ambiguous clusters (emoji) */
	calibrate_client(ch_, session_, rows_);
	/* startup flash animation before the captcha / list */
	startup_flash();
	/* start from the CURRENT event counters: a fresh session must not
	 * replay old bells / path events / redraws */
	seen_version_ = get_version();
	seen_event_id_ = g_ev_seq.load();
	seen_bell_id_ = g_bell_seq.load();
	seen_msg_id_ = g_msg_seq.load();
	seen_online_ = g_online_epoch.load();
	seen_lock_ = g_lock_epoch.load();
	refresh();
	/* login captcha, if requested */
	if (g_captcha_timeout > 0) {
		captcha_weak_ = g_captcha_weak;
		if (captcha_weak_) {
			unsigned sd = (unsigned)time(nullptr) ^ (unsigned)(uintptr_t)this
			            ^ (unsigned)rand();
			captcha_code_.clear();
			for (int i = 0; i < 8; i++)
				captcha_code_ += (char)('0' + (int)(art_rand(sd) * 10) % 10);
		} else {
			captcha_new_code();
		}
		captcha_deadline_ = time(nullptr) + g_captcha_timeout;
		captcha_art_.clear();
		captcha_art_w_ = captcha_art_h_ = 0;
		prompt_label_ = "captcha: ";
		prompt_buf_.clear();
		prompt_cx_ = 0;
		prompt_scroll_ = 0;
		status_ = captcha_weak_ ? "type the digits shown"
		                        : "type the characters in the picture";
		mode_ = CAPTCHA;
	}
	try {
		render();
		for (;;) {
			poll_resize();
			KeyEvent ev;
			if (!next_key(ev))
				break;
			if (ev.key == Key::Tick) {
				std::string tt = title_text();
				if (u8width(tt) > cols_) {
					int W = u8width(tt + "   ");
					if (W > 0)
						title_scroll_ = (title_scroll_ + 1) % W;
				}
				if (sel_ >= 0 && sel_ < (int)entries_.size()) {
					const Entry &e = entries_[sel_];
					int W = u8width(sanitize_ctrl(e.name)
					                + (e.isdir ? "/" : "") + "   ");
					if (W > 0)
						name_scroll_ = (name_scroll_ + 1) % W;
				}
				{
					std::string st = sanitize_ctrl(status_);
					if (u8width(st) > cols_) {
						int W = u8width(st + "   ");
						if (W > 0)
							msg_scroll_ = (msg_scroll_ + 1) % W;
					}
				}
			} else if (ev.key == Key::Update) {
				/* sandbox changed by someone else: the version check below
				 * refreshes and pushes the redraw immediately */
			} else if (ev.key == Key::Redraw) {
				/* online count changed: only the title bar needs a repaint */
			} else if (mode_ == CAPTCHA) handle_captcha(ev);
			else if (mode_ == LIST) handle_list(ev);
			else if (mode_ == EDITOR) handle_editor(ev);
			else if (mode_ == PROMPT) handle_prompt(ev);
			else handle_confirm(ev);
			if (get_version() != seen_version_) {
				seen_version_ = get_version();
				process_events();
				if (mode_ != EDITOR) refresh();
			}
			process_bells();
			process_messages();
			/* the peer may be gone even though libssh has not noticed */
			if (!sock_alive(ssh_get_fd(session_)))
				break;
			/* captcha: count down and disconnect on timeout */
			if (mode_ == CAPTCHA && time(nullptr) >= captcha_deadline_) {
				status_ = "captcha timed out";
				render();
				ssh_session_set_disconnect_message(session_,
				                                   "captcha timeout");
				break;
			}
			if (quit_)
				break;
			render();
		}
	} catch (int) {
	}
	/* release any editor lock this connection still holds */
	if (!edit_lock_.empty()) {
		filelock_release(edit_lock_);
		edit_lock_.clear();
	}
	{
		std::lock_guard<std::mutex> lk(g_sess_mtx);
		g_sessions.erase(sid_);
	}
	std::string bye = "\x1b[?25h\x1b[2J\x1b[H"
	                  "Disconnect from sshfm.\r\nSee you.\r\n";
	channel_write_all(ch_, bye);
}

/* ------------------------------------------------------------------ */
/* SSH server                                                          */
/* ------------------------------------------------------------------ */

static std::string g_root;

static std::string client_ip(ssh_session session)
{
	int fd = ssh_get_fd(session);
	if (fd < 0) return "?";
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) return "?";
	char buf[64] = {0};
	if (ss.ss_family == AF_INET)
		inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, buf, sizeof(buf));
	else if (ss.ss_family == AF_INET6)
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, buf, sizeof(buf));
	return buf[0] ? std::string(buf) : std::string("?");
}

static void handle_session(ssh_session session)
{
	OnlineGuard online;
	ssh_channel chan = nullptr;
	bool authed = false;
	int cols = 80, rows = 24;
	std::string user = "root";
	std::string ip = client_ip(session);

	/* TCP keepalive as a backstop so dead peers are detected even if the
	 * SSH-level heartbeat cannot run */
	{
		int fd = ssh_get_fd(session);
		if (fd >= 0) {
			int on = 1, idle = 5, intv = 2, cnt = 3;
			setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on);
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intv, sizeof intv);
			setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
		}
	}

	/* never look into the real ~/.ssh (host keys are provided explicitly
	 * and this keeps libssh from resolving the user's home directory) */
	ssh_options_set(session, SSH_OPTIONS_SSH_DIR, "/dev/null");
	/* the authentication phase has its own limit (-auth): a client that
	 * connects and sends nothing must not keep the session (and its online
	 * count) alive, so bound the socket operations too */
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &g_auth_timeout);


	if (ssh_handle_key_exchange(session) != SSH_OK) {
		ssh_disconnect(session);
		ssh_free(session);
		return;
	}
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD |
	                           SSH_AUTH_METHOD_PUBLICKEY);

	/* the authentication phase has its own limit (-auth, default 30s):
	 * poll so a client that never authenticates is dropped */
	ssh_set_blocking(session, 0);
	time_t auth_deadline = time(nullptr) + g_auth_timeout;
	while (true) {
		ssh_message msg = ssh_message_get(session);
		if (!msg) {
			if (!sock_alive(ssh_get_fd(session)))
				break;                 /* the peer is gone */
			if (!authed && time(nullptr) >= auth_deadline) {
				/* dedicated auth-phase exit: send a disconnect with a
				 * reason so the client reports it */
				ssh_session_set_disconnect_message(session,
				                                   "authentication timeout");
				break;
			}
			usleep(10000);
			continue;
		}
		int type = ssh_message_type(msg);
		if (type == SSH_REQUEST_SERVICE) {
			ssh_message_service_reply_success(msg);
			ssh_message_free(msg);
			continue;
		}
		if (type == SSH_REQUEST_AUTH) {
			const char *u = ssh_message_auth_user(msg);
			if (u && u[0]) user = u;
			int sub = ssh_message_subtype(msg);
			if (sub == SSH_AUTH_METHOD_PASSWORD) {
				/* any password is accepted */
				ssh_message_auth_reply_success(msg, 0);
				authed = true;
			} else if (sub == SSH_AUTH_METHOD_PUBLICKEY) {
				/* any key is accepted: answer the probe, then the signed
				 * request authenticates */
				if (ssh_message_auth_publickey_state(msg) ==
				    SSH_PUBLICKEY_STATE_NONE) {
					ssh_message_auth_reply_pk_ok_simple(msg);
				} else {
					ssh_message_auth_reply_success(msg, 0);
					authed = true;
				}
			} else {
				/* "none" etc.: list what we take and reply with a failure */
				ssh_message_auth_set_methods(msg,
					SSH_AUTH_METHOD_PASSWORD |
					SSH_AUTH_METHOD_PUBLICKEY);
				ssh_message_reply_default(msg);
			}
			ssh_message_free(msg);
			continue;
		}
		if (!authed) { ssh_message_free(msg); continue; }
		if (type == SSH_REQUEST_CHANNEL_OPEN) {
			int sub = ssh_message_subtype(msg);
			ssh_channel newch = ssh_message_channel_request_open_reply_accept(msg);
			if (sub == SSH_CHANNEL_SESSION) {
				if (newch) chan = newch;
			} else if (newch) {
				ssh_channel_send_eof(newch);
				ssh_channel_close(newch);
				ssh_channel_free(newch);
			}
			ssh_message_free(msg);
			continue;
		}
		if (type == SSH_REQUEST_CHANNEL && chan) {
			int sub = ssh_message_subtype(msg);
			if (sub == SSH_CHANNEL_REQUEST_PTY) {
				int c = ssh_message_channel_request_pty_width(msg);
				int r = ssh_message_channel_request_pty_height(msg);
				if (c > 0) cols = c;
				if (r > 0) rows = r;
				ssh_message_channel_request_reply_success(msg);
			} else if (sub == SSH_CHANNEL_REQUEST_SHELL ||
			           sub == SSH_CHANNEL_REQUEST_EXEC) {
				ssh_message_channel_request_reply_success(msg);
				ssh_message_free(msg);
				Sandbox sb(g_root);
				UI ui(sb, ip, session);
				try { ui.run(chan, cols, rows); } catch (...) {}
				break;
			} else {
				ssh_message_reply_default(msg);
			}
			ssh_message_free(msg);
			continue;
		}
		ssh_message_reply_default(msg);
		ssh_message_free(msg);
	}

	if (chan) {
		ssh_channel_send_eof(chan);
		ssh_channel_close(chan);
		ssh_channel_free(chan);
	}
	ssh_disconnect(session);
	ssh_free(session);
}

static void usage(const char *prog)
{
	printf("usage: %s [-dir rootdir] [-port port] [-time +H|-H] [-captcha [SEC]]\n"
	       "\n"
	       "  -dir D      sandbox root directory (default: ./data)\n"
	       "  -port N     ssh listen port           (default: 2222)\n"
	       "  -time X     timezone offset in hours for displayed times,\n"
	       "              e.g. -time +8 or -time -5 (default: +0 = UTC)\n"
	       "  -captcha [S]   require a captcha before the TUI (default 30s)\n"
	       "  -auth N       authentication phase timeout (default 60s)\n"
	       "  -captcha [S]L  weak check: type 8 shown digits instead\n"
	       "  --help      show this help and exit\n",
	       prog);
}

int main(int argc, char **argv)
{
	const char *root = nullptr;
	int port = -1;
	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		if (a == "--help" || a == "-h") {
			usage(argv[0]);
			return 0;
		}
		if (a == "-time") {
			if (i + 1 >= argc) {
				fprintf(stderr, "sshfm: -time needs an argument, e.g. -time +8\n");
				return 1;
			}
			const char *v = argv[++i];
			char *end = nullptr;
			long off = strtol(v, &end, 10);
			if (end == v || *end != '\0' || off < -14 || off > 14) {
				fprintf(stderr, "sshfm: invalid timezone '%s' (use e.g. +8 or -5)\n", v);
				return 1;
			}
			g_tz_offset = (int)off;
			continue;
		}
		if (a == "-captcha") {
			/* "-captcha" -> 30s art captcha, "-captcha 60" -> 60s,
			 * "-captcha L" / "-captcha 30L" -> weak digit check */
			g_captcha_timeout = 30;
			g_captcha_weak = false;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				std::string v = argv[++i];
				if (!v.empty() && (v.back() == 'L' || v.back() == 'l')) {
					g_captcha_weak = true;
					v.pop_back();
				}
				if (!v.empty()) {
					char *end = nullptr;
					long n = strtol(v.c_str(), &end, 10);
					if (end == v.c_str() || *end != '\0' || n < 1 || n > 86400) {
						fprintf(stderr, "sshfm: invalid captcha argument '%s'\n",
						        argv[i]);
						return 1;
					}
					g_captcha_timeout = (int)n;
				}
			}
			continue;
		}
		if (a == "-auth") {
			if (i + 1 >= argc) {
				fprintf(stderr, "sshfm: -auth needs a timeout in seconds\n");
				return 1;
			}
			char *end = nullptr;
			long v = strtol(argv[++i], &end, 10);
			if (end == argv[i] || *end != '\0' || v < 1 || v > 86400) {
				fprintf(stderr, "sshfm: invalid auth timeout '%s'\n", argv[i]);
				return 1;
			}
			g_auth_timeout = (int)v;
			continue;
		}
		if (a == "-dir") {
			if (i + 1 >= argc) {
				fprintf(stderr, "sshfm: -dir needs an argument\n");
				return 1;
			}
			root = argv[++i];
			continue;
		}
		if (a == "-port") {
			if (i + 1 >= argc) {
				fprintf(stderr, "sshfm: -port needs an argument\n");
				return 1;
			}
			char *end = nullptr;
			long v = strtol(argv[++i], &end, 10);
			if (end == argv[i] || *end != '\0' || v < 1 || v > 65535) {
				fprintf(stderr, "sshfm: invalid port '%s'\n", argv[i]);
				return 1;
			}
			port = (int)v;
			continue;
		}
		fprintf(stderr, "sshfm: unknown argument '%s'\n", argv[i]);
		usage(argv[0]);
		return 1;
	}
	if (!root)
		root = "./data";
	if (port < 0)
		port = 2222;

	/* dev helper: render a sample captcha with every embedded font */
	char full[PATH_MAX];
	if (realpath(root, full))
		g_root = full;
	else
		g_root = root;
	mkdir(g_root.c_str(), 0755);
	{
		struct stat sb;
		if (stat(g_root.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode)) {
			fprintf(stderr, "sshfm: root '%s' is not a directory\n", g_root.c_str());
			return 1;
		}
	}
	fprintf(stderr, "sshfm: root=%s port=%d tz=%+d auth=%d captcha=%d%s\n",
        g_root.c_str(), port, g_tz_offset, g_auth_timeout, g_captcha_timeout,
        g_captcha_weak ? "L" : "");

	ssh_bind bind = ssh_bind_new();
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BANNER, "sshfm_1.1");
	/* no fake version banner: libssh announces itself, so clients do not
	 * apply OpenSSH-specific expectations we cannot satisfy */

	/* Persistent host key next to the binary: the fingerprint is fixed
	 * across restarts instead of changing on every boot. */
	std::string keypath = "sshfm_hostkey";
	{
		char self[PATH_MAX];
		ssize_t sn = readlink("/proc/self/exe", self, sizeof(self) - 1);
		if (sn > 0) {
			self[sn] = '\0';
			char *slash = strrchr(self, '/');
			if (slash) {
				*slash = '\0';
				keypath = std::string(self) + "/sshfm_hostkey";
			}
		}
	}
	ssh_key key = nullptr;
	if (ssh_pki_import_privkey_file(keypath.c_str(), nullptr, nullptr, nullptr, &key) != SSH_OK || !key) {
		key = nullptr;
		if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &key) != SSH_OK)
			if (ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &key) != SSH_OK) {
				fprintf(stderr, "sshfm: cannot generate host key\n");
				return 1;
			}
		ssh_pki_export_privkey_file(key, nullptr, nullptr, nullptr, keypath.c_str());
		fprintf(stderr, "sshfm: wrote host key %s\n", keypath.c_str());
	}
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key);

	if (ssh_bind_listen(bind) < 0) {
		fprintf(stderr, "sshfm: listen failed: %s\n", ssh_get_error(bind));
		return 1;
	}
	for (;;) {
		ssh_session s = ssh_new();
		if (!s) continue;
		if (ssh_bind_accept(bind, s) != SSH_OK) { ssh_free(s); continue; }
		std::thread(handle_session, s).detach();
	}
}
