/* 
 * bpfcc - tiny C -> eBPF compiler. Output: ELF64 relocatable object (EM_BPF).
 * Only libc needed. No BTF, no CO-RE. Targets kernels 4.4 .. 5.4 (ISA v1 by default).
 *
 *   cc -O2 -o bpfcc bpfcc.c
 *   bpfcc prog.c -o prog.o [-S] [-DNAME[=V]] [-Idir] [-mv2]
 *
 * -S   print disassembly      -mv2  allow JLT/JLE/JSLT/JSLE (kernel >= 4.14)
 * -V   (optional last stage) load every program into the running kernel to run the verifier, then close
 *      it again: nothing is attached or pinned. Prints the verifier log on rejection. Needs root. -T N forces the
 *      program type (default: guessed from the SEC name).
 * -legacy-maps   old 'maps' section instead of BTF-defined maps (.maps + minimal .BTF; needed by libbpf >= 1.0)
 *
 * Language: C subset (incl. switch/case/default and goto; switch = compare chain, works on any kernel). int types (no float), pointers, arrays, struct/union (no bitfields),
 * typedef, enum, #define/#if/#include, local init lists, if/while/for/do, break/continue,
 * ?: && || ++ -- op=, casts, sizeof, offsetof. Non-SEC functions are inlined at call sites.
 * Extras: bpf_printk(fmt,...), memset/memcpy (const size), bpf_htons & co, __helper(id,...),
 *   '#pragma unroll [N]' before for/while (N = max iterations, default 16).
 * Maps (libbpf 1.x style, no CO-RE):  struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
 *   __type(key, u32); __type(value, u64); } m SEC(".maps");   -> .maps + tiny generated .BTF
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef __linux__
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#endif

typedef long long i64;
typedef unsigned long long u64;
typedef unsigned char u8;

static const char *cur_file = "?";
static int cur_line = 0;
static void die(const char *fmt, ...)
{
	va_list a;
	va_start(a, fmt);
	fprintf(stderr, "%s:%d: error: ", cur_file, cur_line);
	vfprintf(stderr, fmt, a);
	fputc('\n', stderr);
	exit(1);
}

static void *xcalloc(size_t n)
{
	void *p = calloc(1, n ? n : 1);
	if (!p)
	{
		perror("calloc");
		exit(1);
	}
	return p;
}

static char *xstrndup(const char *s, int n)
{
	char *r = xcalloc(n + 1);
	memcpy(r, s, n);
	return r;
}

static char *xstrdup(const char *s)
{
	return xstrndup(s, (int)strlen(s));
}

#define VEC(T) struct { T *p; int n, cap; }
#define PUSH(v, x) do { if ((v).n == (v).cap) { (v).cap = (v).cap ? (v).cap * 2 : 16; \
  (v).p = realloc((v).p, sizeof(*(v).p) * (v).cap); if (!(v).p) { perror("realloc"); exit(1); } } \
  (v).p[(v).n++] = (x); } while (0)

/* ======================= lexer / preprocessor ======================= */
enum
{ T_EOF = 0, T_NUM = 1, T_ID = 2, T_STR = 3, T_UNROLL = 4, T_SHL =
		256, T_SHR, T_LE, T_GE, T_EQ, T_NE,
	T_LAND, T_LOR, T_INC, T_DEC, T_ARROW, T_HASHHASH, T_ADDA, T_SUBA, T_MULA, T_DIVA, T_MODA,
	T_ANDA, T_ORA, T_XORA,
	T_SHLA, T_SHRA, T_ELL
};
typedef struct
{
	int k, line, uns, lng, slen;
	const char *file;
	char *s;
	i64 v;
} Tok;
typedef VEC(Tok) TokV;

	 static const struct
	 {
		 const char *s;
		 int k;
	 } PT[] =
{
	{
	"##", T_HASHHASH},
	{
	"<<=", T_SHLA},
	{
	">>=", T_SHRA},
	{
	"...", T_ELL},
	{
	"<<", T_SHL},
	{
	">>", T_SHR},
	{
	"<=", T_LE},
	{
	">=", T_GE},
	{
	"==", T_EQ},
	{
	"!=", T_NE},
	{
	"&&", T_LAND},
	{
	"||", T_LOR},
	{
	"++", T_INC},
	{
	"--", T_DEC},
	{
	"->", T_ARROW},
	{
	"+=", T_ADDA},
	{
	"-=", T_SUBA},
	{
	"*=", T_MULA},
	{
	"/=", T_DIVA},
	{
	"%=", T_MODA},
	{
	"&=", T_ANDA},
	{
	"|=", T_ORA},
	{
	"^=", T_XORA},
	{
0, 0}};

static int esc(const char **pp)
{
	const char *p = *pp;
	int c = *p++;
	switch (c)
	{
	case 'n':
		c = '\n';
		break;
	case 't':
		c = '\t';
		break;
	case 'r':
		c = '\r';
		break;
	case 'a':
		c = 7;
		break;
	case 'b':
		c = 8;
		break;
	case 'f':
		c = 12;
		break;
	case 'v':
		c = 11;
		break;
	case 'x':
		c = 0;
		while (isxdigit((u8) * p))
		{
			c = c * 16 + (isdigit((u8) * p) ? *p - '0' : tolower(*p) - 'a' + 10);
			p++;
		}
		break;
	default:
		if (c >= '0' && c <= '7')
		{
			c -= '0';
			for (int i = 0; i < 2 && *p >= '0' && *p <= '7'; i++)
				c = c * 8 + *p++ - '0';
		}
	}
	*pp = p;
	return c & 0xff;
}

static void lex(const char *p, const char *file, int line, TokV * o)
{
	while (*p)
	{
		if (isspace((u8) * p))
		{
			p++;
			continue;
		}
		Tok t;
		memset(&t, 0, sizeof t);
		t.file = file;
		t.line = line;
		cur_file = file;
		cur_line = line;
		if (isalpha((u8) * p) || *p == '_')
		{
			const char *q = p;
			while (isalnum((u8) * q) || *q == '_')
				q++;
			t.k = T_ID;
			t.s = xstrndup(p, (int)(q - p));
			p = q;
		}
		else if (isdigit((u8) * p))
		{
			const char *q = p;
			u64 v = 0;
			int nd = 0;
			if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			{
				q = p + 2;
				nd = 1;
				while (isxdigit((u8) * q))
				{
					v = v * 16 + (isdigit((u8) * q) ? *q - '0' : tolower(*q) - 'a' + 10);
					q++;
				}
			}
			else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B'))
			{
				q = p + 2;
				nd = 1;
				while (*q == '0' || *q == '1')
					v = v * 2 + (*q++ - '0');
			}
			else if (p[0] == '0')
			{
				nd = 1;
				while (*q >= '0' && *q <= '7')
					v = v * 8 + (*q++ - '0');
			}
			else
				while (isdigit((u8) * q))
					v = v * 10 + (*q++ - '0');
			while (*q == 'u' || *q == 'U' || *q == 'l' || *q == 'L')
			{
				if (tolower(*q) == 'u')
					t.uns = 1;
				else
					t.lng++;
				q++;
			}
			if (*q == '.' || *q == 'e')
				die("floating point is not supported");
			t.k = T_NUM;
			t.v = (i64) v;
			t.slen = nd;
			p = q;
		}
		else if (*p == '"')
		{
			char *b = xcalloc(strlen(p) + 1);
			int n = 0;
			p++;
			while (*p && *p != '"')
			{
				if (*p == '\\')
				{
					p++;
					b[n++] = (char)esc(&p);
				}
				else
					b[n++] = *p++;
			}
			if (*p != '"')
				die("unterminated string");
			p++;
			t.k = T_STR;
			t.s = b;
			t.slen = n;
		}
		else if (*p == '\'')
		{
			p++;
			int c;
			if (*p == '\\')
			{
				p++;
				c = esc(&p);
			}
			else
				c = *p++;
			if (*p != '\'')
				die("bad char literal");
			p++;
			t.k = T_NUM;
			t.v = (signed char)c;
		}
		else
		{
			int i;
			for (i = 0; PT[i].s; i++)
				if (!strncmp(p, PT[i].s, strlen(PT[i].s)))
					break;
			if (PT[i].s)
			{
				t.k = PT[i].k;
				p += strlen(PT[i].s);
			}
			else
				t.k = (u8) * p++;
		}
		PUSH(*o, t);
	}
}

typedef struct
{
	char *name;
	int func, np, var;
	char *pn[16];
	TokV body;
} Macro;
static VEC(Macro *) macros;
	 static Macro *findm(const char *n)
{
	for (int i = macros.n - 1; i >= 0; i--)
		if (macros.p[i] && !strcmp(macros.p[i]->name, n))
			return macros.p[i];
	return 0;
}

static void expand(Tok * in, int n, TokV * out, Macro ** hide, int nh)
{
	for (int i = 0; i < n; i++)
	{
		Tok t = in[i];
		Macro *m;
		if (t.k == T_ID && (m = findm(t.s)))
		{
			int h = 0;
			for (int j = 0; j < nh; j++)
				if (hide[j] == m)
					h = 1;
			if (!h)
			{
				Macro *h2[64];
				if (nh > 62)
					die("macro nesting too deep");
				if (nh)
					memcpy(h2, hide, nh * sizeof *hide);
				h2[nh] = m;
				if (!m->func)
				{
					expand(m->body.p, m->body.n, out, h2, nh + 1);
					continue;
				}
				if (i + 1 < n && in[i + 1].k == '(')
				{
					TokV arg[18];
					memset(arg, 0, sizeof arg);
					int na = 0, d = 0, j = i + 2;
					if (j < n && in[j].k == ')')
					{
					}
					else
					{
						for (; j < n; j++)
						{
							Tok a = in[j];
							if (a.k == '(')
								d++;
							else if (a.k == ')')
							{
								if (d == 0)
									break;
								d--;
							}
							else if (a.k == ',' && d == 0 && !(m->var && na >= m->np))
							{
								na++;
								continue;
							}
							PUSH(arg[na], a);
						}
						na++;
					}
					if (j >= n)
						die("unterminated macro call %s", m->name);
					TokV sub;
					memset(&sub, 0, sizeof sub);
					for (int b = 0; b < m->body.n; b++)
					{
						Tok bt = m->body.p[b];
						int pi = -1;
						if (bt.k == T_ID)
						{
							for (int q = 0; q < m->np; q++)
								if (!strcmp(bt.s, m->pn[q]))
									pi = q;
							if (m->var && !strcmp(bt.s, "__VA_ARGS__"))
								pi = m->np;
						}
						if (pi >= 0)
						{
							for (int q = 0; q < arg[pi].n; q++)
								PUSH(sub, arg[pi].p[q]);
						}
						else
							PUSH(sub, bt);
					}
					TokV glued;
					memset(&glued, 0, sizeof glued);	/* token pasting: a ## 
														   b -> ab, after
														   parameter
														   substitution */
					for (int b = 0; b < sub.n; b++)
					{
						if (sub.p[b].k == T_HASHHASH && b > 0 && b + 1 < sub.n && glued.n > 0)
						{
							Tok *prev = &glued.p[glued.n - 1];
							Tok next = sub.p[++b];
							char buf[512], tb1[32], tb2[32];
							const char *ps =
								prev->s ? prev->s : (prev->k ==
													 T_NUM ? (snprintf(tb1, sizeof tb1, "%lld",
																	   (long long)prev->v),
															  tb1) : "");
							const char *ns =
								next.s ? next.s : (next.k ==
												   T_NUM
												   ? (snprintf
													  (tb2, sizeof tb2, "%lld", (long long)next.v),
													  tb2) : "");
							snprintf(buf, sizeof buf, "%s%s", ps, ns);
							prev->s = xstrdup(buf);
							prev->k = T_ID;
						}
						else
							PUSH(glued, sub.p[b]);
					}
					free(sub.p);
					sub = glued;
					expand(sub.p, sub.n, out, h2, nh + 1);
					i = j;
					continue;
				}
			}
		}
		PUSH(*out, t);
	}
}

static TokV pending, final_;
static char *incdirs[32];
static int nincdirs;
static void flush(void)
{
	expand(pending.p, pending.n, &final_, 0, 0);
	pending.n = 0;
}

static void do_define(char *s, const char *file, int line)
{
	while (isspace((u8) * s))
		s++;
	char *q = s;
	while (isalnum((u8) * q) || *q == '_')
		q++;
	Macro *m = xcalloc(sizeof *m);
	m->name = xstrndup(s, (int)(q - s));
	if (*q == '(')
	{
		m->func = 1;
		q++;
		for (;;)
		{
			while (isspace((u8) * q))
				q++;
			if (*q == ')')
			{
				q++;
				break;
			}
			if (q[0] == '.' && q[1] == '.' && q[2] == '.')
			{
				m->var = 1;
				q += 3;
			}
			else
			{
				char *e = q;
				while (isalnum((u8) * e) || *e == '_')
					e++;
				if (e == q || m->np >= 15)
					die("bad macro params");
				m->pn[m->np++] = xstrndup(q, (int)(e - q));
				q = e;
			}
			while (isspace((u8) * q))
				q++;
			if (*q == ',')
				q++;
		}
	}
	lex(q, file, line, &m->body);
	PUSH(macros, m);
}

/* #if expression evaluator */
static Tok *ex;
static int exi, exn;
static i64 ev(int minp);
static i64 evu(void)
{
	if (exi >= exn)
		die("bad #if expression");
	Tok t = ex[exi++];
	if (t.k == T_NUM)
		return t.v;
	if (t.k == T_ID)
		return 0;
	if (t.k == '(')
	{
		i64 v = ev(0);
		if (exi < exn && ex[exi].k == ')')
			exi++;
		return v;
	}
	if (t.k == '!')
		return !evu();
	if (t.k == '-')
		return -evu();
	if (t.k == '~')
		return ~evu();
	if (t.k == '+')
		return evu();
	die("bad #if expression");
	return 0;
}

static int eprec(int k)
{
	switch (k)
	{
	case T_LOR:
		return 1;
	case T_LAND:
		return 2;
	case '|':
		return 3;
	case '^':
		return 4;
	case '&':
		return 5;
	case T_EQ:
	case T_NE:
		return 6;
	case '<':
	case '>':
	case T_LE:
	case T_GE:
		return 7;
	case T_SHL:
	case T_SHR:
		return 8;
	case '+':
	case '-':
		return 9;
	case '*':
	case '/':
	case '%':
		return 10;
	}
	return 0;
}

static i64 ev(int minp)
{
	i64 l = evu();
	while (exi < exn)
	{
		int k = ex[exi].k, p = eprec(k);
		if (!p || p < minp)
			break;
		exi++;
		i64 r = ev(p + 1);
		switch (k)
		{
		case T_LOR:
			l = l || r;
			break;
		case T_LAND:
			l = l && r;
			break;
		case '|':
			l |= r;
			break;
		case '^':
			l ^= r;
			break;
		case '&':
			l &= r;
			break;
		case T_EQ:
			l = l == r;
			break;
		case T_NE:
			l = l != r;
			break;
		case '<':
			l = l < r;
			break;
		case '>':
			l = l > r;
			break;
		case T_LE:
			l = l <= r;
			break;
		case T_GE:
			l = l >= r;
			break;
		case T_SHL:
			l <<= r;
			break;
		case T_SHR:
			l >>= r;
			break;
		case '+':
			l += r;
			break;
		case '-':
			l -= r;
			break;
		case '*':
			l *= r;
			break;
		case '/':
			l = r ? l / r : 0;
			break;
		case '%':
			l = r ? l % r : 0;
			break;
		}
	}
	return l;
}

static i64 eval_if(char *s, const char *file, int line)
{
	TokV a, b, c;
	memset(&a, 0, sizeof a);
	memset(&b, 0, sizeof b);
	memset(&c, 0, sizeof c);
	lex(s, file, line, &a);
	for (int i = 0; i < a.n; i++)
	{
		if (a.p[i].k == T_ID && !strcmp(a.p[i].s, "defined"))
		{
			int par = i + 1 < a.n && a.p[i + 1].k == '(';
			int j = i + 1 + par;
			if (j >= a.n || a.p[j].k != T_ID)
				die("bad defined");
			Tok t = a.p[j];
			t.k = T_NUM;
			t.v = findm(a.p[j].s) != 0;
			PUSH(b, t);
			i = j + par;
		}
		else
			PUSH(b, a.p[i]);
	}
	expand(b.p, b.n, &c, 0, 0);
	ex = c.p;
	exi = 0;
	exn = c.n;
	return ev(0);
}

static char *read_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return 0;
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *b = xcalloc(n + 1);
	if (fread(b, 1, n, f) != (size_t) n)
		n = 0;
	fclose(f);
	return b;
}

static void strip_comments(char *s)
{
	char *r = s, *w = s;
	while (*r)
	{
		if (*r == '"' || *r == '\'')
		{
			char q = *r;
			*w++ = *r++;
			while (*r && *r != q && *r != '\n')
			{
				if (*r == '\\' && r[1])
					*w++ = *r++;
				*w++ = *r++;
			}
			if (*r == q)
				*w++ = *r++;
		}
		else if (r[0] == '/' && r[1] == '/')
		{
			while (*r && *r != '\n')
				r++;
		}
		else if (r[0] == '/' && r[1] == '*')
		{
			r += 2;
			while (*r && !(r[0] == '*' && r[1] == '/'))
			{
				if (*r == '\n')
					*w++ = '\n';
				r++;
			}
			if (*r)
				r += 2;
			*w++ = ' ';
		}
		else
			*w++ = *r++;
	}
	*w = 0;
}

static void pp_text(char *txt, const char *file, int depth);
static void pp_include(const char *name, int quoted, const char *from, int depth)
{
	char path[1024];
	char *src = 0;
	if (depth > 16)
		die("#include too deep");
	if (quoted)
	{
		const char *sl = strrchr(from, '/');
		if (sl)
			snprintf(path, sizeof path, "%.*s/%s", (int)(sl - from), from, name);
		else
			snprintf(path, sizeof path, "%s", name);
		src = read_file(path);
	}
	for (int i = 0; !src && i < nincdirs; i++)
	{
		snprintf(path, sizeof path, "%s/%s", incdirs[i], name);
		src = read_file(path);
	}
	if (!src)
		return;					/* unknown headers (linux/bpf.h etc.) are
								   ignored: builtin prelude covers the basics */
	pp_text(src, xstrdup(path), depth + 1);
}

typedef struct
{
	int taken, parent;
} Cond;
static void pp_text(char *txt, const char *file, int depth)
{
	Cond cs[64];
	int nc = 0, active = 1, lineno = 1;
	strip_comments(txt);
	char *p = txt;
	while (*p)
	{
		int startline = lineno;
		char *ln = xcalloc(strlen(p) + 2);
		size_t n = 0;
		for (;;)
		{
			char *e = strchr(p, '\n');
			size_t len = e ? (size_t) (e - p) : strlen(p);
			memcpy(ln + n, p, len);
			n += len;
			p += len;
			if (*p)
			{
				p++;
				lineno++;
			}
			if (n && ln[n - 1] == '\\')
			{
				ln[n - 1] = ' ';
				if (!*p)
					break;
				continue;
			}
			break;
		}
		ln[n] = 0;
		cur_file = file;
		cur_line = startline;
		char *s = ln;
		while (isspace((u8) * s))
			s++;
		if (*s == '#')
		{
			s++;
			while (isspace((u8) * s))
				s++;
			char *d = s;
			while (isalpha((u8) * s))
				s++;
			char *dn = xstrndup(d, (int)(s - d));
			while (isspace((u8) * s))
				s++;
			if (!strcmp(dn, "if") || !strcmp(dn, "ifdef") || !strcmp(dn, "ifndef"))
			{
				int par = active, val = 0;
				if (par)
				{
					if (dn[2] == 'd')
					{
						char *e = s;
						while (isalnum((u8) * e) || *e == '_')
							e++;
						char *nm = xstrndup(s, (int)(e - s));
						val = findm(nm) != 0;
					}
					else if (dn[2] == 'n')
					{
						char *e = s;
						while (isalnum((u8) * e) || *e == '_')
							e++;
						char *nm = xstrndup(s, (int)(e - s));
						val = findm(nm) == 0;
					}
					else
						val = eval_if(s, file, startline) != 0;
				}
				if (nc >= 63)
					die("#if nesting too deep");
				cs[nc].parent = par;
				cs[nc].taken = val;
				nc++;
				active = par && val;
			}
			else if (!strcmp(dn, "elif"))
			{
				if (!nc)
					die("#elif without #if");
				Cond *c = &cs[nc - 1];
				if (c->parent && !c->taken)
				{
					int v = eval_if(s, file, startline) != 0;
					c->taken = v;
					active = v;
				}
				else
					active = 0;
			}
			else if (!strcmp(dn, "else"))
			{
				if (!nc)
					die("#else without #if");
				Cond *c = &cs[nc - 1];
				active = c->parent && !c->taken;
				c->taken = 1;
			}
			else if (!strcmp(dn, "endif"))
			{
				if (!nc)
					die("#endif without #if");
				active = cs[--nc].parent;
			}
			else if (active)
			{
				if (!strcmp(dn, "define"))
				{
					flush();
					do_define(s, file, startline);
				}
				else if (!strcmp(dn, "undef"))
				{
					flush();
					char *e = s;
					while (isalnum((u8) * e) || *e == '_')
						e++;
					char *nm = xstrndup(s, (int)(e - s));
					for (int i = 0; i < macros.n; i++)
						if (macros.p[i] && !strcmp(macros.p[i]->name, nm))
							macros.p[i] = 0;
				}
				else if (!strcmp(dn, "include"))
				{
					flush();
					char close = *s == '<' ? '>' : '"';
					int quoted = *s == '"';
					if (*s == '<' || *s == '"')
					{
						char *e = strchr(s + 1, close);
						if (e)
							pp_include(xstrndup(s + 1, (int)(e - s - 1)), quoted, file, depth);
					}
				}
				else if (!strcmp(dn, "pragma"))
				{
					if (!strncmp(s, "unroll", 6))
					{
						Tok t;
						memset(&t, 0, sizeof t);
						t.k = T_UNROLL;
						t.file = file;
						t.line = startline;
						t.v = atoi(s + 6);
						PUSH(pending, t);
					}
				}
				else if (!strcmp(dn, "error"))
					die("#error %s", s);
			}
		}
		else if (active)
			lex(ln, file, startline, &pending);
	}
	if (nc)
		die("unterminated #if");
}

/* ======================= types / AST ======================= */
typedef struct Type Type;
typedef struct Member Member;
typedef struct Node Node;
typedef struct Var Var;
typedef struct Func Func;
enum
{ TY_VOID, TY_INT, TY_PTR, TY_ARR, TY_STRUCT };
struct Type
{
	int kind, size, align, uns, len, isunion, complete, hasmd, mdn;
	char *mdname[16];
	int mdisu[16];
	i64 mdval[16];
	Type *base;
	Member *mem;
};
struct Member
{
	char *name;
	Type *ty;
	int off;
	Member *next;
};
struct Var
{
	char *name;
	Type *ty, *mdty;
	int off, reg, global, addr, sym;
	char *sec;
	u8 *data;
	i64 usecount;
	int hot, hotrank;
};
struct Func
{
	char *name;
	Type *ret;
	Var **params;
	int np, defined, hot_computed, hot_count;
	Node *body;
	char *sec;
};
enum
{ N_NUM, N_STR, N_VAR, N_ADDR, N_DEREF, N_MEMBER, N_CAST, N_ADD, N_SUB, N_MUL, N_DIV, N_MOD, N_AND,
	N_OR, N_XOR,
	N_SHL, N_SHR, N_EQ, N_NE, N_LT, N_LE, N_GT, N_GE, N_LAND, N_LOR, N_NOT, N_NEG, N_BNOT, N_COND,
	N_COMMA, N_ASSIGN,
	N_CALL, N_IF, N_WHILE, N_DO, N_FOR, N_RETURN, N_BREAK, N_CONT, N_BLOCK, N_EXPR, N_DECL, N_ZERO,
	N_NOP, N_INIT, N_ITEM, N_SWITCH, N_CASE, N_GOTO, N_LABEL
};
enum
{ BI_PRINTK = 1, BI_MEMSET, BI_MEMCPY, BI_BSWAP, BI_XADD };
struct Node
{
	int op;
	Type *ty, *cty;
	Node *l, *r, *c, *next, *body;
	i64 val;
	Var *var;
	char *str;
	Member *mem;
	Node *cnext, *cl, *ct;
	Node *args[8];
	int nargs, aop, post, noop, unroll, hid, bi;
	char hret;
	Func *fn;
};

static Type *ty_void, *ty_char, *ty_uchar, *ty_short, *ty_ushort, *ty_int, *ty_uint, *ty_long,
	*ty_ulong;
static Type *mkty(int k, int sz, int uns)
{
	Type *t = xcalloc(sizeof *t);
	t->kind = k;
	t->size = sz;
	t->align = sz ? sz : 1;
	t->uns = uns;
	t->complete = 1;
	return t;
}

static Type *ptr_to(Type * b)
{
	Type *t = mkty(TY_PTR, 8, 1);
	t->base = b;
	return t;
}

static Type *array_of(Type * b, int n)
{
	Type *t = mkty(TY_ARR, n < 0 ? 0 : b->size * n, 0);
	t->base = b;
	t->len = n;
	t->align = b->align;
	return t;
}

static void init_types(void)
{
	ty_void = mkty(TY_VOID, 1, 0);
	ty_char = mkty(TY_INT, 1, 0);
	ty_uchar = mkty(TY_INT, 1, 1);
	ty_short = mkty(TY_INT, 2, 0);
	ty_ushort = mkty(TY_INT, 2, 1);
	ty_int = mkty(TY_INT, 4, 0);
	ty_uint = mkty(TY_INT, 4, 1);
	ty_long = mkty(TY_INT, 8, 0);
	ty_ulong = mkty(TY_INT, 8, 1);
}

typedef struct
{
	char *name;
	int kind;
	Type *ty;
	i64 val;
	Var *var;
	Func *fn;
} Sym;
enum
{ S_VAR, S_TYPEDEF, S_ENUM, S_FUNC };
typedef struct
{
	char *n;
	Type *t;
} Tag;
static VEC(Sym) syms;
	 static VEC(int) scopes;
	 static VEC(Tag) tags;
	 static VEC(Func *) funcs;
	 static VEC(Var *) globals;
	 static void push_scope(void)
{
	PUSH(scopes, syms.n);
}

static void pop_scope(void)
{
	syms.n = scopes.p[--scopes.n];
}

static Sym *lookup(const char *n)
{
	for (int i = syms.n - 1; i >= 0; i--)
		if (!strcmp(syms.p[i].name, n))
			return &syms.p[i];
	return 0;
}

static Sym *addsym(const char *n, int kind)
{
	Sym s;
	memset(&s, 0, sizeof s);
	s.name = xstrdup(n);
	s.kind = kind;
	PUSH(syms, s);
	return &syms.p[syms.n - 1];
}

static Tok *T;
static int pos;
static Func *curfn;
static int legacy_maps;
static Node *cur_sw;
static int kind(void)
{
	cur_file = T[pos].file;
	cur_line = T[pos].line;
	return T[pos].k;
}

static int isid(const char *s)
{
	return T[pos].k == T_ID && !strcmp(T[pos].s, s);
}

static int acc(int k)
{
	if (kind() == k)
	{
		pos++;
		return 1;
	}
	return 0;
}

static int acc_id(const char *s)
{
	if (isid(s))
	{
		pos++;
		return 1;
	}
	return 0;
}

static void expect(int k)
{
	if (!acc(k))
		die("syntax error: expected '%c' near '%s'", k < 256 ? k : '?', T[pos].k == T_ID
			|| T[pos].k == T_STR ? T[pos].s : "token");
}

static Node *newn(int op, Type * ty)
{
	Node *n = xcalloc(sizeof *n);
	n->op = op;
	n->ty = ty;
	return n;
}

static i64 normv(i64 v, Type * t)
{
	if (t->kind != TY_INT && t->kind != TY_PTR)
		return v;
	switch (t->size)
	{
	case 1:
		return t->uns ? (i64) (u8) v : (i64) (signed char)v;
	case 2:
		return t->uns ? (i64) (unsigned short)v : (i64) (short)v;
	case 4:
		return t->uns ? (i64) (unsigned)v : (i64) (int)v;
	} return v;
}

static Node *num(i64 v, Type * t)
{
	Node *n = newn(N_NUM, t);
	n->val = normv(v, t);
	return n;
}

static int cev(Node * n, i64 * o)
{
	i64 a, b;
	switch (n->op)
	{
	case N_NUM:
		*o = n->val;
		return 1;
	case N_CAST:
		if (!cev(n->l, &a))
			return 0;
		*o = n->ty->kind == TY_VOID ? a : normv(a, n->ty);
		return 1;
	case N_NEG:
		if (!cev(n->l, &a))
			return 0;
		*o = normv(-a, n->ty);
		return 1;
	case N_BNOT:
		if (!cev(n->l, &a))
			return 0;
		*o = normv(~a, n->ty);
		return 1;
	case N_NOT:
		if (!cev(n->l, &a))
			return 0;
		*o = !a;
		return 1;
	case N_COND:
		if (!cev(n->c, &a))
			return 0;
		return cev(a ? n->l : n->r, o);
	case N_LAND:
	case N_LOR:
		if (!cev(n->l, &a) || !cev(n->r, &b))
			return 0;
		*o = n->op == N_LAND ? (a && b) : (a || b);
		return 1;
	case N_ADD:
	case N_SUB:
	case N_MUL:
	case N_DIV:
	case N_MOD:
	case N_AND:
	case N_OR:
	case N_XOR:
	case N_SHL:
	case N_SHR:
	case N_EQ:
	case N_NE:
	case N_LT:
	case N_LE:
	case N_GT:
	case N_GE:
		{
			if (!cev(n->l, &a) || !cev(n->r, &b))
				return 0;
			u64 ua = a, ub = b;
			int u = n->cty ? n->cty->uns : n->ty->uns;
			i64 r = 0;
			switch (n->op)
			{
			case N_ADD:
				r = a + b;
				break;
			case N_SUB:
				r = a - b;
				break;
			case N_MUL:
				r = a * b;
				break;
			case N_DIV:
				if (!b)
					return 0;
				r = u ? (i64) (ua / ub) : a / b;
				break;
			case N_MOD:
				if (!b)
					return 0;
				r = u ? (i64) (ua % ub) : a % b;
				break;
			case N_AND:
				r = a & b;
				break;
			case N_OR:
				r = a | b;
				break;
			case N_XOR:
				r = a ^ b;
				break;
			case N_SHL:
				if (b < 0 || b > 63)
					return 0;
				r = (i64) (ua << b);
				break;
			case N_SHR:
				if (b < 0 || b > 63)
					return 0;
				r = n->ty->uns ? (i64) (ua >> b) : a >> b;
				break;
			case N_EQ:
				r = a == b;
				break;
			case N_NE:
				r = a != b;
				break;
			case N_LT:
				r = u ? ua < ub : a < b;
				break;
			case N_LE:
				r = u ? ua <= ub : a <= b;
				break;
			case N_GT:
				r = u ? ua > ub : a > b;
				break;
			case N_GE:
				r = u ? ua >= ub : a >= b;
				break;
			}
			*o = normv(r, n->ty);
			return 1;
		}
	}
	return 0;
}

static Node *fold(Node * n)
{
	i64 v;
	if (n->op != N_NUM && n->ty && n->ty->kind != TY_VOID && cev(n, &v))
		return num(v, n->ty);
	return n;
}

static i64 const_expr(Node * n)
{
	i64 v;
	if (!cev(n, &v))
		die("constant expression expected");
	return v;
}

static int needs_norm(Type * from, Type * to)
{
	if (to->kind == TY_VOID || to->size >= 8)
		return 0;
	int fs = (from->kind == TY_PTR
			  || from->kind == TY_ARR) ? 8 : from->size, fu =
		(from->kind == TY_PTR) ? 1 : from->uns;
	if (to->size == fs && to->uns == fu)
		return 0;
	if (to->size > fs && (fu || !to->uns))
		return 0;
	return 1;
}

static Node *cast_to(Node * n, Type * t)
{
	if (n->ty == t)
		return n;
	if (t->kind == TY_STRUCT || t->kind == TY_ARR || n->ty->kind == TY_STRUCT)
		die("invalid cast/conversion");
	if (n->op == N_NUM && t->kind != TY_VOID)
		return num(n->val, t);
	Node *c = newn(N_CAST, t);
	c->l = n;
	c->noop = t->kind == TY_VOID ? 0 : !needs_norm(n->ty, t);
	return c;
}

static Type *promote(Type * t)
{
	return (t->kind == TY_INT && t->size < 4) ? ty_int : t;
}

static Type *common(Type * a, Type * b)
{
	a = promote(a);
	b = promote(b);
	if (a->size == 8 || b->size == 8)
		return ((a->size == 8 && a->uns) || (b->size == 8 && b->uns)) ? ty_ulong : ty_long;
	return (a->uns || b->uns) ? ty_uint : ty_int;
}

static int islv(Node * n)
{
	return n->op == N_VAR || n->op == N_DEREF || n->op == N_MEMBER;
}

static void mark_addr(Node * n)
{
	while (n->op == N_MEMBER)
		n = n->l;
	if (n->op == N_VAR)
		n->var->addr = 1;
}

static Node *rvalue(Node * n)
{
	if (n->ty->kind == TY_ARR)
	{
		mark_addr(n);
		Node *a = newn(N_ADDR, ptr_to(n->ty->base));
		a->l = n;
		return a;
	}
	return n;
}

static int isptr(Type * t)
{
	return t->kind == TY_PTR;
}

static Node *mk_arith(int op, Node * a, Node * b)
{
	if (a->ty->kind != TY_INT || b->ty->kind != TY_INT)
		die("invalid operands to binary operator");
	Type *t = common(a->ty, b->ty);
	Node *n = newn(op, t);
	n->l = cast_to(a, t);
	n->r = cast_to(b, t);
	return fold(n);
}

static Node *mk_shift(int op, Node * a, Node * b)
{
	if (a->ty->kind != TY_INT || b->ty->kind != TY_INT)
		die("invalid shift operands");
	Type *t = promote(a->ty);
	Node *n = newn(op, t);
	n->l = cast_to(a, t);
	n->r = b;
	return fold(n);
}

static int psize(Type * t)
{
	int s = t->base->size;
	return s ? s : 1;
}

static Node *mk_add(Node * a, Node * b)
{
	if (!isptr(a->ty) && isptr(b->ty))
	{
		Node *t = a;
		a = b;
		b = t;
	}
	if (isptr(a->ty))
	{
		if (b->ty->kind != TY_INT)
			die("invalid pointer arithmetic");
		b = cast_to(b, ty_long);
		if (psize(a->ty) != 1)
			b = mk_arith(N_MUL, b, num(psize(a->ty), ty_long));
		Node *n = newn(N_ADD, a->ty);
		n->l = a;
		n->r = b;
		return n;
	}
	return mk_arith(N_ADD, a, b);
}

static Node *mk_sub(Node * a, Node * b)
{
	if (isptr(a->ty) && isptr(b->ty))
	{
		Node *n = newn(N_SUB, ty_long);
		n->l = cast_to(a, ty_long);
		n->r = cast_to(b, ty_long);
		return mk_arith(N_DIV, n, num(psize(a->ty), ty_long));
	}
	if (isptr(a->ty))
	{
		b = cast_to(b, ty_long);
		if (psize(a->ty) != 1)
			b = mk_arith(N_MUL, b, num(psize(a->ty), ty_long));
		Node *n = newn(N_SUB, a->ty);
		n->l = a;
		n->r = b;
		return n;
	}
	return mk_arith(N_SUB, a, b);
}

static Node *mk_cmp(int op, Node * a, Node * b)
{
	Type *t;
	if (isptr(a->ty) || isptr(b->ty))
		t = ty_ulong;
	else
	{
		if (a->ty->kind != TY_INT || b->ty->kind != TY_INT)
			die("invalid comparison");
		t = common(a->ty, b->ty);
	}
	Node *n = newn(op, ty_int);
	n->l = cast_to(a, t);
	n->r = cast_to(b, t);
	n->cty = t;
	return fold(n);
}

static Node *mk_binary(int k, Node * l, Node * r)
{
	l = rvalue(l);
	r = rvalue(r);
	switch (k)
	{
	case '+':
		return mk_add(l, r);
	case '-':
		return mk_sub(l, r);
	case '*':
		return mk_arith(N_MUL, l, r);
	case '/':
		return mk_arith(N_DIV, l, r);
	case '%':
		return mk_arith(N_MOD, l, r);
	case '&':
		return mk_arith(N_AND, l, r);
	case '|':
		return mk_arith(N_OR, l, r);
	case '^':
		return mk_arith(N_XOR, l, r);
	case T_SHL:
		return mk_shift(N_SHL, l, r);
	case T_SHR:
		return mk_shift(N_SHR, l, r);
	case T_EQ:
		return mk_cmp(N_EQ, l, r);
	case T_NE:
		return mk_cmp(N_NE, l, r);
	case '<':
		return mk_cmp(N_LT, l, r);
	case '>':
		return mk_cmp(N_GT, l, r);
	case T_LE:
		return mk_cmp(N_LE, l, r);
	case T_GE:
		return mk_cmp(N_GE, l, r);
	case T_LAND:
	case T_LOR:
		{
			Node *n = newn(k == T_LAND ? N_LAND : N_LOR, ty_int);
			n->l = l;
			n->r = r;
			return fold(n);
		}
	}
	die("bad binary operator");
	return 0;
}

static Node *mk_assign(Node * lv, Node * rhs, int aop)
{
	if (!islv(lv) || lv->ty->kind == TY_ARR)
		die("lvalue required");
	Node *n = newn(N_ASSIGN, lv->ty);
	n->l = lv;
	n->aop = aop;
	rhs = rvalue(rhs);
	if (!aop)
	{
		if (lv->ty->kind == TY_STRUCT)
		{
			if (rhs->ty != lv->ty)
				die("incompatible struct assignment");
			n->r = rhs;
		}
		else
			n->r = cast_to(rhs, lv->ty);
	}
	else if (isptr(lv->ty))
	{
		if (aop != N_ADD && aop != N_SUB)
			die("invalid pointer op-assign");
		Node *r = cast_to(rhs, ty_long);
		if (psize(lv->ty) != 1)
			r = mk_arith(N_MUL, r, num(psize(lv->ty), ty_long));
		n->r = r;
		n->cty = ty_ulong;
	}
	else
	{
		if (lv->ty->kind != TY_INT || rhs->ty->kind != TY_INT)
			die("invalid op-assign operands");
		if (aop == N_SHL || aop == N_SHR)
		{
			n->cty = promote(lv->ty);
			n->r = rhs;
		}
		else
		{
			n->cty = common(lv->ty, rhs->ty);
			n->r = cast_to(rhs, n->cty);
		}
	}
	return n;
}

static Node *mk_incdec(Node * lv, int delta, int post)
{
	Node *n = mk_assign(lv, num(1, ty_int), delta > 0 ? N_ADD : N_SUB);
	n->post = post;
	return n;
}

static Node *mk_deref(Node * p)
{
	p = rvalue(p);
	if (!isptr(p->ty))
		die("dereference of non-pointer");
	if (p->ty->base->kind == TY_VOID)
		die("dereference of void*");
	Node *n = newn(N_DEREF, p->ty->base);
	n->l = p;
	return n;
}

static Node *mk_member(Node * b, const char *name)
{
	if (b->ty->kind != TY_STRUCT)
		die("member access on non-struct");
	for (Member * m = b->ty->mem; m; m = m->next)
		if (!strcmp(m->name, name))
		{
			Node *n = newn(N_MEMBER, m->ty);
			n->l = b;
			n->mem = m;
			return n;
		}
	die("no member named '%s'", name);
	return 0;
}

/* ---------- declarations ---------- */
static Node *parse_assign(void);
static Node *parse_expr(void);
static Node *parse_cond(void);
static Node *parse_unary(void);
static Node *parse_stmt(void);
static Node *parse_block(void);
static Type *declspec(int *isstatic, int *istd, char **sec, int *packed);
static Type *declarator(Type * base, char **name);
static Type *parse_typename(void);

static int is_typestart(int p)
{
	Tok *t = &T[p];
	if (t->k != T_ID)
		return 0;
	static const char *kw[] =
		{ "void", "char", "short", "int", "long", "signed", "unsigned", "_Bool", "struct", "union",
		"enum", "const",
		"volatile", "static", "extern", "typedef", "register", "inline", "__inline", "__inline__",
		"__always_inline", "__attribute__", 0
	};
	for (int i = 0; kw[i]; i++)
		if (!strcmp(t->s, kw[i]))
			return 1;
	Sym *s = lookup(t->s);
	return s && s->kind == S_TYPEDEF;
}

static void parse_attrs(char **sec, int *packed)
{
	while (isid("__attribute__") || isid("__attribute")
		   || ((isid("SEC") || isid("__section")) && T[pos + 1].k == '('))
	{
		if (!isid("__attribute__") && !isid("__attribute"))
		{
			pos += 2;
			if (kind() != T_STR)
				die("SEC needs a string");
			if (sec)
				*sec = xstrdup(T[pos].s);
			pos++;
			expect(')');
			continue;
		}
		pos++;
		expect('(');
		expect('(');
		while (kind() != ')')
		{
			if (kind() != T_ID)
				die("bad attribute");
			char *a = T[pos++].s;
			if (kind() == '(')
			{
				pos++;
				if ((!strcmp(a, "section") || !strcmp(a, "__section__")) && kind() == T_STR && sec)
					*sec = xstrdup(T[pos].s);
				int d = 1;
				while (d)
				{
					int k = kind();
					if (k == T_EOF)
						die("unexpected eof");
					if (k == '(')
						d++;
					if (k == ')')
						d--;
					pos++;
				}
			}
			else if ((!strcmp(a, "packed") || !strcmp(a, "__packed__")) && packed)
				*packed = 1;
			if (!acc(','))
				break;
		}
		expect(')');
		expect(')');
	}
}

static i64 align_up(i64 v, i64 a)
{
	return (v + a - 1) / a * a;
}

static Type *find_tag(const char *n)
{
	for (int i = tags.n - 1; i >= 0; i--)
		if (!strcmp(tags.p[i].n, n))
			return tags.p[i].t;
	return 0;
}

static void add_tag(const char *n, Type * t)
{
	Tag g;
	g.n = xstrdup(n);
	g.t = t;
	PUSH(tags, g);
}

static Type *struct_spec(void)
{
	int isunion = T[pos].s[0] == 'u';
	pos++;
	int packed = 0;
	parse_attrs(0, &packed);
	char *name = 0;
	if (kind() == T_ID)
		name = T[pos++].s;
	Type *t = name ? find_tag(name) : 0;
	if (kind() != '{')
	{
		if (!name)
			die("struct needs a name or body");
		if (!t)
		{
			t = mkty(TY_STRUCT, 0, 0);
			t->complete = 0;
			t->isunion = isunion;
			add_tag(name, t);
		}
		return t;
	}
	pos++;
	if (!t || t->complete)
	{
		t = mkty(TY_STRUCT, 0, 0);
		t->complete = 0;
		t->isunion = isunion;
		if (name)
			add_tag(name, t);
	}
	Member **tail = &t->mem;
	while (kind() != '}')
	{
		if (kind() == T_EOF)
			die("unexpected eof in struct");
		if (isid("__uint") || isid("__type"))
		{						/* libbpf-style BTF map syntax -> legacy map
								   def (no BTF emitted) */
			int isu = T[pos].s[2] == 'u';
			pos++;
			expect('(');
			if (kind() != T_ID)
				die("map attribute name expected");
			char *fn = T[pos++].s;
			expect(',');
			i64 v = isu ? const_expr(parse_cond()) : parse_typename()->size;
			expect(')');
			expect(';');
			t->hasmd = 1;
			if (t->mdn >= 16)
				die("too many map attributes");
			t->mdname[t->mdn] = fn;
			t->mdisu[t->mdn] = isu;
			t->mdval[t->mdn] = v;
			t->mdn++;
			continue;
		}
		Type *base = declspec(0, 0, 0, 0);
		if (kind() == ';' && base->kind == TY_STRUCT)
		{						/* anonymous struct/union member: flatten */
			for (Member * m = base->mem; m; m = m->next)
			{
				Member *c = xcalloc(sizeof *c);
				*c = *m;
				c->next = 0;
				c->off = m->off;
				*tail = c;
				tail = &c->next;
			}
			/* offsets fixed up below via anon marker */
			pos++;
			continue;
		}
		for (;;)
		{
			char *nm = 0;
			Type *ty = declarator(base, &nm);
			if (kind() == ':')
				die("bitfields are not supported");
			if (!nm)
				die("member name expected");
			if (!ty->complete && ty->kind == TY_STRUCT)
				die("member has incomplete type");
			Member *m = xcalloc(sizeof *m);
			m->name = nm;
			m->ty = ty;
			*tail = m;
			tail = &m->next;
			if (!acc(','))
				break;
		}
		expect(';');
	}
	pos++;
	parse_attrs(0, &packed);
	/* layout (anonymous flattened members keep their relative offsets;
	   recompute naively as sequential) */
	i64 cur = 0, maxsz = 0;
	int al = 1;
	for (Member * m = t->mem; m; m = m->next)
	{
		int ma = packed ? 1 : m->ty->align;
		if (ma > al)
			al = ma;
		if (t->isunion)
		{
			m->off = 0;
			if (m->ty->size > maxsz)
				maxsz = m->ty->size;
		}
		else
		{
			cur = align_up(cur, ma);
			m->off = (int)cur;
			cur += m->ty->size;
		}
	}
	t->align = al;
	t->size = (int)align_up(t->isunion ? maxsz : cur, al);
	t->complete = 1;
	return t;
}

static Type *enum_spec(void)
{
	pos++;
	char *name = 0;
	if (kind() == T_ID)
		name = T[pos++].s;
	(void)name;
	if (acc('{'))
	{
		i64 v = 0;
		while (kind() != '}')
		{
			if (kind() != T_ID)
				die("enum constant expected");
			char *nm = T[pos++].s;
			if (acc('='))
				v = const_expr(parse_cond());
			Sym *s = addsym(nm, S_ENUM);
			s->val = v++;
			if (!acc(','))
				break;
		}
		expect('}');
	}
	return ty_int;
}

static int in_list(const char *s, const char **l)
{
	for (; *l; l++)
		if (!strcmp(s, *l))
			return 1;
	return 0;
}

static Type *declspec(int *isstatic, int *istd, char **sec, int *packed)
{
	static const char *ign[] =
		{ "const", "volatile", "extern", "register", "auto", "inline", "__inline", "__inline__",
		"__always_inline",
		"__noinline", "noinline", "restrict", "__restrict", "__restrict__", "__maybe_unused",
		"__unused", "used", "__used", 0
	};
	int nlong = 0, nshort = 0, uns = 0, sgn = 0, base = 0, any = 0;
	Type *ty = 0;
	int d1 = 0, d2 = 0;
	if (!isstatic)
		isstatic = &d1;
	if (!istd)
		istd = &d2;
	for (;;)
	{
		if (kind() != T_ID)
			break;
		char *s = T[pos].s;
		if (!strcmp(s, "static"))
			*isstatic = 1;
		else if (!strcmp(s, "typedef"))
			*istd = 1;
		else if (in_list(s, ign))
		{
		}
		else if (!strcmp(s, "__attribute__") || !strcmp(s, "__attribute"))
		{
			parse_attrs(sec, packed);
			continue;
		}
		else if ((!strcmp(s, "SEC") || !strcmp(s, "__section")) && T[pos + 1].k == '(')
		{
			pos += 2;
			if (kind() != T_STR)
				die("SEC needs a string");
			if (sec)
				*sec = xstrdup(T[pos].s);
			pos++;
			expect(')');
			continue;
		}
		else if (!strcmp(s, "void"))
		{
			base = 1;
			any = 1;
		}
		else if (!strcmp(s, "char"))
		{
			base = 2;
			any = 1;
		}
		else if (!strcmp(s, "int"))
		{
			if (!base)
				base = 3;
			any = 1;
		}
		else if (!strcmp(s, "_Bool"))
		{
			base = 4;
			any = 1;
		}
		else if (!strcmp(s, "long"))
		{
			nlong++;
			any = 1;
		}
		else if (!strcmp(s, "short"))
		{
			nshort++;
			any = 1;
		}
		else if (!strcmp(s, "signed"))
		{
			sgn = 1;
			any = 1;
		}
		else if (!strcmp(s, "unsigned"))
		{
			uns = 1;
			any = 1;
		}
		else if (!strcmp(s, "struct") || !strcmp(s, "union"))
		{
			ty = struct_spec();
			any = 1;
			continue;
		}
		else if (!strcmp(s, "enum"))
		{
			ty = enum_spec();
			any = 1;
			continue;
		}
		else if (!strcmp(s, "float") || !strcmp(s, "double"))
			die("floating point is not supported");
		else
		{
			Sym *sy = lookup(s);
			if (sy && sy->kind == S_TYPEDEF && !any)
			{
				ty = sy->ty;
				any = 1;
			}
			else
				break;
		}
		pos++;
	}
	if (ty)
		return ty;
	if (!any)
		die("type expected near '%s'", T[pos].k == T_ID ? T[pos].s : "token");
	if (base == 1)
		return ty_void;
	if (base == 4)
		return ty_uchar;
	if (base == 2)
		return uns ? ty_uchar : ty_char;
	if (nshort)
		return uns ? ty_ushort : ty_short;
	if (nlong)
		return uns ? ty_ulong : ty_long;
	return uns ? ty_uint : ty_int;
}

static Type *declarator(Type * base, char **name)
{
	while (acc('*'))
	{
		base = ptr_to(base);
		while (isid("const") || isid("volatile") || isid("restrict") || isid("__restrict"))
			pos++;
	}
	*name = 0;
	if (kind() == T_ID
		&& !(is_typestart(pos) && lookup(T[pos].s) && lookup(T[pos].s)->kind == S_TYPEDEF
			 && T[pos + 1].k == ')'))
		*name = T[pos++].s;
	int dims[8], nd = 0;
	while (acc('['))
	{
		if (nd >= 8)
			die("too many dimensions");
		if (kind() == ']')
			dims[nd++] = -1;
		else
			dims[nd++] = (int)const_expr(parse_cond());
		expect(']');
	}
	for (int i = nd - 1; i >= 0; i--)
		base = array_of(base, dims[i]);
	return base;
}

static Type *parse_typename(void)
{
	Type *b = declspec(0, 0, 0, 0);
	char *nm;
	return declarator(b, &nm);
}

/* ---------- expressions ---------- */
typedef struct
{
	const char *n;
	int id;
	char r;
} Helper;
#define H(n, id, r) { "bpf_" #n, id, r }
static const Helper HLP[] = {
	H(map_lookup_elem, 1, 'p'), H(map_update_elem, 2, 'l'), H(map_delete_elem, 3, 'l'),
	H(probe_read, 4, 'l'), H(ktime_get_ns, 5, 'u'),
	H(trace_printk, 6, 'l'), H(get_prandom_u32, 7, 'w'), H(get_smp_processor_id, 8, 'w'),
	H(skb_store_bytes, 9, 'l'), H(l3_csum_replace, 10, 'l'),
	H(l4_csum_replace, 11, 'l'), H(tail_call, 12, 'l'), H(clone_redirect, 13, 'l'),
	H(get_current_pid_tgid, 14, 'u'), H(get_current_uid_gid, 15, 'u'),
	H(get_current_comm, 16, 'l'), H(get_cgroup_classid, 17, 'w'), H(skb_vlan_push, 18, 'l'),
	H(skb_vlan_pop, 19, 'l'), H(skb_get_tunnel_key, 20, 'l'),
	H(skb_set_tunnel_key, 21, 'l'), H(perf_event_read, 22, 'u'), H(redirect, 23, 'l'),
	H(get_route_realm, 24, 'w'), H(perf_event_output, 25, 'l'),
	H(skb_load_bytes, 26, 'l'), H(get_stackid, 27, 'l'), H(csum_diff, 28, 'l'),
	H(skb_get_tunnel_opt, 29, 'l'), H(skb_set_tunnel_opt, 30, 'l'),
	H(skb_change_proto, 31, 'l'), H(skb_change_type, 32, 'l'), H(skb_under_cgroup, 33, 'l'),
	H(get_hash_recalc, 34, 'w'), H(get_current_task, 35, 'u'),
	H(probe_write_user, 36, 'l'), H(current_task_under_cgroup, 37, 'l'), H(skb_change_tail, 38,
																		   'l'), H(skb_pull_data,
																				   39, 'l'),
	H(csum_update, 40, 'l'),
	H(set_hash_invalid, 41, 'l'), H(get_numa_node_id, 42, 'l'), H(skb_change_head, 43, 'l'),
	H(xdp_adjust_head, 44, 'l'), H(probe_read_str, 45, 'l'),
	H(get_socket_cookie, 46, 'u'), H(get_socket_uid, 47, 'w'), H(set_hash, 48, 'l'), H(setsockopt,
																					   49, 'l'),
	H(skb_adjust_room, 50, 'l'),
	H(redirect_map, 51, 'l'), H(sk_redirect_map, 52, 'l'), H(sock_map_update, 53, 'l'),
	H(xdp_adjust_meta, 54, 'l'), H(perf_event_read_value, 55, 'l'),
	H(perf_prog_read_value, 56, 'l'), H(getsockopt, 57, 'l'), H(override_return, 58, 'l'),
	H(sock_ops_cb_flags_set, 59, 'l'), H(msg_redirect_map, 60, 'l'),
	H(msg_apply_bytes, 61, 'l'), H(msg_cork_bytes, 62, 'l'), H(msg_pull_data, 63, 'l'), H(bind, 64,
																						  'l'),
	H(xdp_adjust_tail, 65, 'l'),
	H(skb_get_xfrm_state, 66, 'l'), H(get_stack, 67, 'l'), H(skb_load_bytes_relative, 68, 'l'),
	H(fib_lookup, 69, 'l'), H(sock_hash_update, 70, 'l'),
	H(msg_redirect_hash, 71, 'l'), H(sk_redirect_hash, 72, 'l'), H(lwt_push_encap, 73, 'l'),
	H(lwt_seg6_store_bytes, 74, 'l'),
	H(lwt_seg6_adjust_srh, 75, 'l'), H(lwt_seg6_action, 76, 'l'), H(rc_repeat, 77, 'l'),
	H(rc_keydown, 78, 'l'), H(skb_cgroup_id, 79, 'u'),
	H(get_current_cgroup_id, 80, 'u'), H(get_local_storage, 81, 'p'), H(sk_select_reuseport, 82,
																		'l'),
	H(skb_ancestor_cgroup_id, 83, 'u'),
	H(sk_lookup_tcp, 84, 'p'), H(sk_lookup_udp, 85, 'p'), H(sk_release, 86, 'l'), H(map_push_elem,
																					87, 'l'),
	H(map_pop_elem, 88, 'l'),
	H(map_peek_elem, 89, 'l'), H(msg_push_data, 90, 'l'), H(msg_pop_data, 91, 'l'),
	H(rc_pointer_rel, 92, 'l'), H(spin_lock, 93, 'l'),
	H(spin_unlock, 94, 'l'), H(sk_fullsock, 95, 'p'), H(tcp_sock, 96, 'p'), H(skb_ecn_set_ce, 97,
																			  'l'),
	H(get_listener_sock, 98, 'p'),
	H(skc_lookup_tcp, 99, 'p'), H(tcp_check_syncookie, 100, 'l'), H(sysctl_get_name, 101, 'l'),
	H(sysctl_get_current_value, 102, 'l'),
	H(sysctl_get_new_value, 103, 'l'), H(sysctl_set_new_value, 104, 'l'), H(strtol, 105, 'l'),
	H(strtoul, 106, 'l'), H(sk_storage_get, 107, 'p'),
	H(sk_storage_delete, 108, 'l'), H(send_signal, 109, 'l'), H(tcp_gen_syncookie, 110, 'l'),
	H(skb_output, 111, 'l'),
	H(probe_read_user, 112, 'l'), H(probe_read_kernel, 113, 'l'), H(probe_read_user_str, 114, 'l'),
	H(probe_read_kernel_str, 115, 'l'),
	H(tcp_send_ack, 116, 'l'), H(send_signal_thread, 117, 'l'), H(jiffies64, 118, 'u'),
	H(read_branch_records, 119, 'l'), H(get_ns_current_pid_tgid, 120, 'l'),
	H(xdp_output, 121, 'l'), H(get_netns_cookie, 122, 'u'), H(get_current_ancestor_cgroup_id, 123,
															  'u'), H(sk_assign, 124, 'l'),
	H(ktime_get_boot_ns, 125, 'u'),
	H(seq_printf, 126, 'l'), H(seq_write, 127, 'l'), H(sk_cgroup_id, 128, 'u'),
	H(sk_ancestor_cgroup_id, 129, 'u'),
	H(ringbuf_output, 130, 'l'), H(ringbuf_reserve, 131, 'p'), H(ringbuf_submit, 132, 'l'),
	H(ringbuf_discard, 133, 'l'), H(ringbuf_query, 134, 'u'),
	{0, 0, 0}
};

static Type *numtype(Tok * t)
{
	u64 v = (u64) t->v;
	int dec = !t->slen;
	if (t->lng || v > 0xFFFFFFFFULL)
		return (t->uns || v > 0x7FFFFFFFFFFFFFFFULL) ? ty_ulong : ty_long;
	if (v > 0x7FFFFFFFULL)
		return (t->uns || !dec) ? ty_uint : ty_long;
	return t->uns ? ty_uint : ty_int;
}

static Type *enumtype(i64 v)
{
	return (v >= -2147483648LL && v <= 2147483647LL) ? ty_int : (v >= 0
																 && v <=
																 0xFFFFFFFFLL) ? ty_uint : ty_long;
}

typedef struct
{
	char *name;
	int id;
	Type *ret;
	Type **ptypes;
	int np;
} UserHelper;
static VEC(UserHelper) uhelpers;
	 static UserHelper *find_user_helper(const char *nm)
{
	for (int i = 0; i < uhelpers.n; i++)
		if (!strcmp(uhelpers.p[i].name, nm))
			return &uhelpers.p[i];
	return 0;
}

static Node *parse_call(char *nm)
{
	/* current token is '(' */
	pos++;
	if (!strcmp(nm, "offsetof") || !strcmp(nm, "__builtin_offsetof"))
	{
		Type *t = parse_typename();
		expect(',');
		i64 off = 0;
		for (;;)
		{
			if (kind() != T_ID)
				die("member name expected");
			Node *b = newn(N_VAR, t);
			Node *m = mk_member(b, T[pos++].s);
			off += m->mem->off;
			t = m->ty;
			if (acc('.'))
				continue;
			break;
		}
		expect(')');
		return num(off, ty_ulong);
	}
	Node *a[8];
	int na = 0;
	if (!acc(')'))
		for (;;)
		{
			if (na >= 8)
				die("too many call arguments");
			a[na++] = rvalue(parse_assign());
			if (acc(','))
				continue;
			expect(')');
			break;
		}
	Node *n = newn(N_CALL, ty_long);
	n->str = nm;
	n->nargs = na;
	Sym *s = lookup(nm);
	if (s && s->kind == S_FUNC)
	{
		Func *f = s->fn;
		if (na != f->np)
			die("wrong number of arguments to '%s'", nm);
		n->fn = f;
		for (int i = 0; i < na; i++)
			n->args[i] = cast_to(a[i], f->params[i]->ty);
		n->ty = f->ret;
		return n;
	}
	UserHelper *uh = find_user_helper(nm);
	if (uh)
	{
		if (na != uh->np)
			die("wrong number of arguments to '%s'", nm);
		n->hid = uh->id;
		n->hret = 0;
		n->ty = uh->ret;
		for (int i = 0; i < na; i++)
			n->args[i] = cast_to(a[i], uh->ptypes[i]);
		return n;
	}
	for (int i = 0; i < na; i++)
		n->args[i] = a[i];
	if (!strcmp(nm, "__sync_fetch_and_add") || !strcmp(nm, "__sync_add_and_fetch"))
	{
		if (na != 2 || !isptr(a[0]->ty)
			|| (a[0]->ty->base->size != 4 && a[0]->ty->base->size != 8))
			die("__sync_fetch_and_add(u32*/u64* ptr, val)");
		n->bi = BI_XADD;
		n->val = a[0]->ty->base->size;
		n->args[1] = cast_to(a[1], a[0]->ty->base->size == 8 ? ty_ulong : ty_uint);
		return n;
	}
	if (!strcmp(nm, "__builtin_expect"))
	{
		if (na < 1)
			die("bad __builtin_expect");
		return a[0];
	}
	if (!strcmp(nm, "bpf_printk"))
	{
		if (na < 1 || na > 4 || a[0]->op != N_STR)
			die("bpf_printk(\"fmt\", up to 3 args)");
		n->bi = BI_PRINTK;
		return n;
	}
	if (!strcmp(nm, "memset") || !strcmp(nm, "__builtin_memset"))
	{
		if (na != 3)
			die("memset needs 3 args");
		n->bi = BI_MEMSET;
		n->val = const_expr(a[2]);
		n->aop = (int)(const_expr(a[1]) & 0xff);
		n->ty = ty_void;
		return n;
	}
	if (!strcmp(nm, "memcpy") || !strcmp(nm, "__builtin_memcpy"))
	{
		if (na != 3)
			die("memcpy needs 3 args");
		n->bi = BI_MEMCPY;
		n->val = const_expr(a[2]);
		n->ty = ty_void;
		return n;
	}
	int bits = 0;
	if (!strcmp(nm, "bpf_htons") || !strcmp(nm, "bpf_ntohs") || !strcmp(nm, "__builtin_bswap16"))
		bits = 16;
	else if (!strcmp(nm, "bpf_htonl") || !strcmp(nm, "bpf_ntohl")
			 || !strcmp(nm, "__builtin_bswap32"))
		bits = 32;
	else if (!strcmp(nm, "__builtin_bswap64") || !strcmp(nm, "bpf_htonll")
			 || !strcmp(nm, "bpf_ntohll"))
		bits = 64;
	if (bits)
	{
		if (na != 1)
			die("%s needs 1 arg", nm);
		Type *t = bits == 16 ? ty_ushort : bits == 32 ? ty_uint : ty_ulong;
		i64 v;
		if (cev(a[0], &v))
		{
			u64 r = 0, x = (u64) v;
			for (int i = 0; i < bits / 8; i++)
			{
				r = (r << 8) | (x & 0xff);
				x >>= 8;
			} return num((i64) r, t);
		}
		n->bi = BI_BSWAP;
		n->val = bits;
		n->ty = t;
		n->args[0] = cast_to(a[0], t);
		return n;
	}
	if (!strcmp(nm, "__helper"))
	{
		if (na < 1)
			die("__helper(id, ...)");
		n->hid = (int)const_expr(a[0]);
		n->hret = 'l';
		for (int i = 1; i < na; i++)
			n->args[i - 1] = a[i];
		n->nargs = na - 1;
		return n;
	}
	for (int i = 0; HLP[i].n; i++)
		if (!strcmp(HLP[i].n, nm))
		{
			n->hid = HLP[i].id;
			n->hret = HLP[i].r;
			n->ty =
				HLP[i].r == 'p' ? ptr_to(ty_void) : HLP[i].r == 'u' ? ty_ulong : HLP[i].r ==
				'w' ? ty_uint : ty_long;
			return n;
		}
	die("undefined function '%s'", nm);
	return 0;
}

static Node *parse_primary(void)
{
	int k = kind();
	Tok *t = &T[pos];
	if (k == T_NUM)
	{
		pos++;
		return num(t->v, numtype(t));
	}
	if (k == T_STR)
	{
		char *b = xcalloc(1);
		int n = 0;
		while (kind() == T_STR)
		{
			b = realloc(b, n + T[pos].slen + 1);
			memcpy(b + n, T[pos].s, T[pos].slen);
			n += T[pos].slen;
			b[n] = 0;
			pos++;
		}
		Node *s = newn(N_STR, ptr_to(ty_char));
		s->str = b;
		s->val = n;
		return s;
	}
	if (k == '(')
	{
		pos++;
		Node *e = parse_expr();
		expect(')');
		return e;
	}
	if (k == T_ID)
	{
		char *nm = t->s;
		pos++;
		if (kind() == '(')
			return parse_call(nm);
		Sym *s = lookup(nm);
		if (!s)
			die("undeclared identifier '%s'", nm);
		if (s->kind == S_VAR)
		{
			Node *n = newn(N_VAR, s->var->ty);
			n->var = s->var;
			return n;
		}
		if (s->kind == S_ENUM)
			return num(s->val, enumtype(s->val));
		die("'%s' is not a variable", nm);
	}
	die("syntax error near token %d", k);
	return 0;
}

static Node *parse_postfix(void)
{
	Node *n = parse_primary();
	for (;;)
	{
		if (acc('['))
		{
			Node *i = parse_expr();
			expect(']');
			n = mk_deref(mk_add(rvalue(n), rvalue(i)));
		}
		else if (acc('.'))
		{
			if (kind() != T_ID)
				die("member name expected");
			n = mk_member(n, T[pos++].s);
		}
		else if (acc(T_ARROW))
		{
			if (kind() != T_ID)
				die("member name expected");
			n = mk_member(mk_deref(n), T[pos++].s);
		}
		else if (kind() == T_INC || kind() == T_DEC)
		{
			int d = kind() == T_INC ? 1 : -1;
			pos++;
			n = mk_incdec(n, d, 1);
		}
		else
			break;
	}
	return n;
}

static Node *parse_unary(void)
{
	int k = kind();
	if (k == '-')
	{
		pos++;
		Node *e = rvalue(parse_unary());
		if (e->ty->kind != TY_INT)
			die("bad operand to -");
		Type *t = promote(e->ty);
		Node *n = newn(N_NEG, t);
		n->l = cast_to(e, t);
		return fold(n);
	}
	if (k == '+')
	{
		pos++;
		Node *e = rvalue(parse_unary());
		return cast_to(e, promote(e->ty));
	}
	if (k == '~')
	{
		pos++;
		Node *e = rvalue(parse_unary());
		if (e->ty->kind != TY_INT)
			die("bad operand to ~");
		Type *t = promote(e->ty);
		Node *n = newn(N_BNOT, t);
		n->l = cast_to(e, t);
		return fold(n);
	}
	if (k == '!')
	{
		pos++;
		Node *n = newn(N_NOT, ty_int);
		n->l = rvalue(parse_unary());
		return fold(n);
	}
	if (k == '*')
	{
		pos++;
		return mk_deref(parse_unary());
	}
	if (k == '&')
	{
		pos++;
		Node *e = parse_unary();
		if (!islv(e))
			die("cannot take address of rvalue");
		mark_addr(e);
		Node *n = newn(N_ADDR, ptr_to(e->ty));
		n->l = e;
		return n;
	}
	if (k == T_INC || k == T_DEC)
	{
		pos++;
		return mk_incdec(parse_unary(), k == T_INC ? 1 : -1, 0);
	}
	if (isid("sizeof"))
	{
		pos++;
		if (kind() == '(' && is_typestart(pos + 1))
		{
			pos++;
			Type *t = parse_typename();
			expect(')');
			return num(t->size, ty_ulong);
		}
		Node *e = parse_unary();
		return num(e->ty->size, ty_ulong);
	}
	if (k == '(' && is_typestart(pos + 1))
	{
		pos++;
		Type *t = parse_typename();
		expect(')');
		if (kind() == '{')
			die("compound literals are not supported");
		return cast_to(rvalue(parse_unary()), t);
	}
	return parse_postfix();
}

static int binprec(int k)
{
	switch (k)
	{
	case T_LOR:
		return 1;
	case T_LAND:
		return 2;
	case '|':
		return 3;
	case '^':
		return 4;
	case '&':
		return 5;
	case T_EQ:
	case T_NE:
		return 6;
	case '<':
	case '>':
	case T_LE:
	case T_GE:
		return 7;
	case T_SHL:
	case T_SHR:
		return 8;
	case '+':
	case '-':
		return 9;
	case '*':
	case '/':
	case '%':
		return 10;
	}
	return 0;
}

static Node *parse_bin(int minp)
{
	Node *l = parse_unary();
	for (;;)
	{
		int k = kind(), p = binprec(k);
		if (!p || p < minp)
			break;
		pos++;
		Node *r = parse_bin(p + 1);
		l = mk_binary(k, l, r);
	}
	return l;
}

static Node *parse_cond(void)
{
	Node *c = parse_bin(1);
	if (!acc('?'))
		return c;
	Node *a = rvalue(parse_expr());
	expect(':');
	Node *b = rvalue(parse_cond());
	Type *t;
	if (isptr(a->ty))
		t = a->ty;
	else if (isptr(b->ty))
		t = b->ty;
	else if (a->ty->kind == TY_INT && b->ty->kind == TY_INT)
		t = common(a->ty, b->ty);
	else
		t = a->ty;
	Node *n = newn(N_COND, t);
	n->c = rvalue(c);
	if (t->kind == TY_STRUCT || t->kind == TY_VOID)
	{
		n->l = a;
		n->r = b;
	}
	else
	{
		n->l = cast_to(a, t);
		n->r = cast_to(b, t);
	}
	return fold(n);
}

static Node *parse_assign(void)
{
	Node *l = parse_cond();
	int k = kind(), aop = -1;
	switch (k)
	{
	case '=':
		aop = 0;
		break;
	case T_ADDA:
		aop = N_ADD;
		break;
	case T_SUBA:
		aop = N_SUB;
		break;
	case T_MULA:
		aop = N_MUL;
		break;
	case T_DIVA:
		aop = N_DIV;
		break;
	case T_MODA:
		aop = N_MOD;
		break;
	case T_ANDA:
		aop = N_AND;
		break;
	case T_ORA:
		aop = N_OR;
		break;
	case T_XORA:
		aop = N_XOR;
		break;
	case T_SHLA:
		aop = N_SHL;
		break;
	case T_SHRA:
		aop = N_SHR;
		break;
	}
	if (aop < 0)
		return l;
	pos++;
	Node *r = parse_assign();
	return mk_assign(l, r, aop);
}

static Node *parse_expr(void)
{
	Node *n = parse_assign();
	while (acc(','))
	{
		Node *r = parse_assign();
		Node *c = newn(N_COMMA, rvalue(r)->ty);
		c->l = n;
		c->r = rvalue(r);
		n = c;
	}
	return n;
}

/* ---------- initializers ---------- */
static Node *parse_init(void)
{
	if (!acc('{'))
		return parse_assign();
	Node *n = newn(N_INIT, 0);
	Node **t = &n->body;
	while (kind() != '}')
	{
		Node *it = newn(N_ITEM, 0);
		it->val = -1;
		if (acc('.'))
		{
			if (kind() != T_ID)
				die("designator expected");
			it->str = T[pos++].s;
			expect('=');
		}
		else if (kind() == '[')
		{
			pos++;
			it->val = const_expr(parse_cond());
			expect(']');
			expect('=');
		}
		it->l = parse_init();
		*t = it;
		t = &it->next;
		if (!acc(','))
			break;
	}
	expect('}');
	return n;
}

static int init_count(Node * in)
{
	int idx = 0, mx = 0;
	for (Node * it = in->body; it; it = it->next)
	{
		if (it->val >= 0)
			idx = (int)it->val;
		idx++;
		if (idx > mx)
			mx = idx;
	}
	return mx;
}

static Type *infer_len(Type * ty, Node * in)
{
	if (ty->kind == TY_ARR && ty->len < 0 && in)
	{
		if (in->op == N_STR)
			return array_of(ty->base, (int)in->val + 1);
		if (in->op == N_INIT)
			return array_of(ty->base, init_count(in));
		die("cannot infer array size");
	}
	return ty;
}

typedef void (*Leaf) (Type *, Node *, i64);
static void walk_init(Type * ty, Node * in, i64 off, Leaf f)
{
	if (in->op == N_INIT)
	{
		if (ty->kind == TY_ARR)
		{
			i64 idx = 0;
			for (Node * it = in->body; it; it = it->next)
			{
				if (it->val >= 0)
					idx = it->val;
				if (ty->len >= 0 && idx >= ty->len)
					die("excess elements in array initializer");
				walk_init(ty->base, it->l, off + idx * ty->base->size, f);
				idx++;
			}
		}
		else if (ty->kind == TY_STRUCT)
		{
			Member *m = ty->mem;
			for (Node * it = in->body; it; it = it->next)
			{
				if (it->str)
				{
					for (m = ty->mem; m && strcmp(m->name, it->str); m = m->next);
					if (!m)
						die("no member named '%s'", it->str);
				}
				if (!m)
					die("excess elements in struct initializer");
				walk_init(m->ty, it->l, off + m->off, f);
				m = ty->isunion ? 0 : m->next;
			}
		}
		else
		{
			if (in->body)
				walk_init(ty, in->body->l, off, f);
		}
	}
	else if (ty->kind == TY_ARR && in->op == N_STR && ty->base->size == 1)
		f(ty, in, off);
	else
		f(ty, in, off);
}

static Var *newvar(const char *n, Type * t)
{
	Var *v = xcalloc(sizeof *v);
	v->name = xstrdup(n);
	v->ty = t;
	v->reg = -1;
	return v;
}

static Var *il_var;
static Node **il_t;
static Node *estmt(Node * e)
{
	Node *n = newn(N_EXPR, 0);
	n->l = e;
	return n;
}

static void il_add(Node * n)
{
	*il_t = n;
	il_t = &n->next;
}

static void lleaf(Type * ty, Node * e, i64 off)
{
	if (e->op == N_STR && ty->kind == TY_ARR)
	{
		int len = (int)e->val, n = ty->len;
		for (int i = 0; i < len && i < n;)
		{
			int c = ((off + i) % 4 == 0 && i + 4 <= len && i + 4 <= n) ? 4 : ((off + i) % 2 == 0
																			  && i + 2 <= len
																			  && i + 2 <=
																			  n) ? 2 : 1;
			i64 v = 0;
			for (int j = c - 1; j >= 0; j--)
				v = (v << 8) | (u8) e->str[i + j];
			Type *ct = c == 4 ? ty_uint : c == 2 ? ty_ushort : ty_uchar;
			Node *lv = newn(N_VAR, ct);
			lv->var = il_var;
			lv->val = off + i;
			il_add(estmt(mk_assign(lv, num(v, ct), 0)));
			i += c;
		}
		return;
	}
	Node *lv = newn(N_VAR, ty);
	lv->var = il_var;
	lv->val = off;
	il_add(estmt(mk_assign(lv, e, 0)));
}

static Var *gl_var;
static void gleaf(Type * ty, Node * e, i64 off)
{
	if (e->op == N_STR && ty->kind == TY_ARR)
	{
		int n = (int)e->val;
		if (n > ty->len)
			n = ty->len;
		memcpy(gl_var->data + off, e->str, n);
		return;
	}
	Node *r = rvalue(e);
	i64 v;
	if (!cev(r, &v))
		die("global initializer must be constant");
	for (int i = 0; i < ty->size && i < 8; i++)
		gl_var->data[off + i] = (u8) ((u64) v >> (8 * i));
}

/* ---------- statements ---------- */
static Node *parse_local_decl(void)
{
	int st = 0, td = 0;
	char *sec = 0;
	Type *base = declspec(&st, &td, &sec, 0);
	Node *h = 0, **t = &h;
	if (acc(';'))
		return 0;
	for (;;)
	{
		char *nm = 0;
		Type *ty = declarator(base, &nm);
		if (!nm)
			die("variable name expected");
		if (td)
		{
			Sym *s = addsym(nm, S_TYPEDEF);
			s->ty = ty;
		}
		else
		{
			if (st)
				die("static locals are not supported (use maps)");
			Node *in = 0;
			if (acc('='))
				in = parse_init();
			ty = infer_len(ty, in);
			if (ty->kind == TY_VOID || (ty->kind == TY_ARR && ty->len < 0))
				die("bad type for variable '%s'", nm);
			Var *v = newvar(nm, ty);
			Sym *s = addsym(nm, S_VAR);
			s->var = v;
			s->ty = ty;
			Node *d = newn(N_DECL, 0);
			d->var = v;
			*t = d;
			t = &d->next;
			if (in)
			{
				if (in->op == N_INIT || (ty->kind == TY_ARR && in->op == N_STR))
				{
					Node *z = newn(N_ZERO, 0);
					z->var = v;
					*t = z;
					t = &z->next;
					il_var = v;
					il_t = t;
					walk_init(ty, in, 0, lleaf);
					t = il_t;
				}
				else
				{
					Node *lv = newn(N_VAR, ty);
					lv->var = v;
					Node *e = estmt(mk_assign(lv, in, 0));
					*t = e;
					t = &e->next;
				}
			}
		}
		if (!acc(','))
			break;
	}
	expect(';');
	return h;
}

static Node *parse_stmt(void)
{
	int k = kind();
	if (k == T_UNROLL)
	{
		int u = (int)T[pos].v;
		pos++;
		Node *n = parse_stmt();
		if (n->op != N_FOR && n->op != N_WHILE)
			die("#pragma unroll must precede a for/while loop");
		n->unroll = u ? u : -1;
		return n;
	}
	if (k == '{')
		return parse_block();
	if (k == ';')
	{
		pos++;
		return newn(N_NOP, 0);
	}
	if (isid("if"))
	{
		pos++;
		Node *n = newn(N_IF, 0);
		expect('(');
		n->c = rvalue(parse_expr());
		expect(')');
		n->l = parse_stmt();
		if (acc_id("else"))
			n->r = parse_stmt();
		return n;
	}
	if (isid("while"))
	{
		pos++;
		Node *n = newn(N_WHILE, 0);
		expect('(');
		n->c = rvalue(parse_expr());
		expect(')');
		n->body = parse_stmt();
		return n;
	}
	if (isid("do"))
	{
		pos++;
		Node *n = newn(N_DO, 0);
		n->body = parse_stmt();
		if (!acc_id("while"))
			die("'while' expected");
		expect('(');
		n->c = rvalue(parse_expr());
		expect(')');
		expect(';');
		return n;
	}
	if (isid("for"))
	{
		pos++;
		expect('(');
		push_scope();
		Node *n = newn(N_FOR, 0);
		if (!acc(';'))
		{
			if (is_typestart(pos))
				n->l = parse_local_decl();
			else
			{
				n->l = estmt(parse_expr());
				expect(';');
			}
		}
		if (kind() != ';')
			n->c = rvalue(parse_expr());
		expect(';');
		if (kind() != ')')
			n->r = parse_expr();
		expect(')');
		n->body = parse_stmt();
		pop_scope();
		return n;
	}
	if (isid("return"))
	{
		pos++;
		Node *n = newn(N_RETURN, 0);
		if (kind() != ';')
		{
			Node *e = rvalue(parse_expr());
			n->l = curfn->ret->kind == TY_VOID ? e : cast_to(e, curfn->ret);
		}
		expect(';');
		return n;
	}
	if (isid("break"))
	{
		pos++;
		expect(';');
		return newn(N_BREAK, 0);
	}
	if (isid("continue"))
	{
		pos++;
		expect(';');
		return newn(N_CONT, 0);
	}
	if (isid("switch"))
	{
		pos++;
		expect('(');
		Node *n = newn(N_SWITCH, 0);
		Node *e = rvalue(parse_expr());
		if (e->ty->kind != TY_INT)
			die("switch needs an integer expression");
		n->cty = promote(e->ty);
		n->c = cast_to(e, n->cty);
		expect(')');
		Node *old = cur_sw;
		cur_sw = n;
		n->body = parse_stmt();
		cur_sw = old;
		return n;
	}
	if (isid("case") || isid("default"))
	{
		if (!cur_sw)
			die("case/default outside switch");
		Node *n = newn(N_CASE, 0);
		int isd = T[pos].s[0] == 'd';
		pos++;
		if (!isd)
			n->val = const_expr(parse_cond());
		expect(':');
		if (isd)
		{
			if (cur_sw->r)
				die("duplicate default");
			n->aop = 1;
			cur_sw->r = n;
		}
		else
		{
			if (cur_sw->ct)
				cur_sw->ct->cnext = n;
			else
				cur_sw->cl = n;
			cur_sw->ct = n;
		}
		n->body = kind() == '}' ? newn(N_NOP, 0) : parse_stmt();
		return n;
	}
	if (isid("goto"))
	{
		pos++;
		if (kind() != T_ID)
			die("label name expected");
		Node *n = newn(N_GOTO, 0);
		n->str = T[pos++].s;
		expect(';');
		return n;
	}
	if (kind() == T_ID && T[pos + 1].k == ':')
	{
		Node *n = newn(N_LABEL, 0);
		n->str = T[pos].s;
		pos += 2;
		n->body = kind() == '}' ? newn(N_NOP, 0) : parse_stmt();
		return n;
	}
	if (is_typestart(pos))
	{
		Node *b = newn(N_BLOCK, 0);
		b->post = 1;
		b->body = parse_local_decl();
		return b;
	}
	Node *e = parse_expr();
	expect(';');
	return estmt(e);
}

static Node *parse_block(void)
{
	expect('{');
	push_scope();
	Node *b = newn(N_BLOCK, 0);
	Node **t = &b->body;
	while (kind() != '}')
	{
		if (kind() == T_EOF)
			die("unexpected end of file");
		Node *s = (is_typestart(pos) && T[pos + 1].k != ':') ? parse_local_decl() : parse_stmt();
		*t = s;
		while (*t)
			t = &(*t)->next;
	}
	pos++;
	pop_scope();
	return b;
}

/* ---------- user-declared helper shims ---------- */
/* Classic kernel-samples / early-libbpf style: static RET (*name)(ARGS) =
   (void *) N; Calling 'name' then compiles to a plain 'call N' helper call,
   same as bpfcc's own __helper(N, ...) or a name recognized from the built-in 
   HLP[] table. If 'name' happens to match a name bpfcc already knows, N must
   match the known id (a mismatch is almost certainly a typo, so it's a hard
   error); any other name is accepted as-is, registering a new custom helper - 
   useful for ids a patched kernel adds beyond upstream. The declaration
   itself produces no code or storage: nothing ever reads this "variable" as
   data, only ever calls through it, so there is nothing to emit for it. */
/* true if the upcoming tokens are '( * ID ) (' right after a type - the one
   shape a normal declarator never produces on its own (a bare '(' there is
   otherwise always a syntax error), so this is safe to check unconditionally
   with no risk of misreading an ordinary declaration. */
static int looks_like_helper_decl(void)
{
	int p = pos;
	while (T[p].k == '*')
		p++;					/* skip past the return type's own pointer
								   stars, e.g. 'void *(*name)(...)' */
	return T[p].k == '(' && T[p + 1].k == '*' && T[p + 2].k == T_ID && T[p + 3].k == ')'
		&& T[p + 4].k == '(';
}

static void parse_user_helper_decl(Type * ret)
{
	while (acc('*'))
		ret = ptr_to(ret);
	pos++;
	pos++;
	char *nm = T[pos++].s;
	pos++;						/* '(' '*' ID ')' */
	expect('(');
	Type *ptypes[16];
	int np = 0;
	if (isid("void") && T[pos + 1].k == ')')
		pos += 2;
	else if (!acc(')'))
		for (;;)
		{
			if (np >= 16)
				die("too many parameters in helper declaration '%s'", nm);
			Type *pb = declspec(0, 0, 0, 0);
			char *pn = 0;
			Type *pty = declarator(pb, &pn);
			if (pty->kind == TY_ARR)
				pty = ptr_to(pty->base);
			ptypes[np++] = pty;
			if (acc(','))
				continue;
			expect(')');
			break;
		}
	expect('=');
	Node *in = parse_cond();
	i64 id;
	if (!cev(in, &id))
		die("helper '%s' must be initialized with a compile-time constant id", nm);
	expect(';');
	for (int i = 0; HLP[i].n; i++)
		if (!strcmp(HLP[i].n, nm) && HLP[i].id != (int)id)
			die("helper '%s' redeclared with id %lld, but the compiler already knows it as id %d",
				nm, (long long)id, HLP[i].id);
	if (find_user_helper(nm))
		die("helper '%s' declared more than once", nm);
	if (uhelpers.n >= 256)
		die("too many helper declarations");
	UserHelper uh;
	uh.name = xstrdup(nm);
	uh.id = (int)id;
	uh.ret = ret;
	uh.np = np;
	uh.ptypes = xcalloc(sizeof(Type *) * np);
	memcpy(uh.ptypes, ptypes, sizeof(Type *) * np);
	PUSH(uhelpers, uh);
}

/* ---------- top level ---------- */
static void parse_top(void)
{
	while (kind() != T_EOF)
	{
		int st = 0, td = 0, packed = 0;
		char *sec = 0;
		Type *base = declspec(&st, &td, &sec, &packed);
		if (acc(';'))
			continue;
		if (looks_like_helper_decl())
		{
			parse_user_helper_decl(base);
			continue;
		}
		for (;;)
		{
			char *nm = 0;
			Type *ty = declarator(base, &nm);
			if (!nm)
				die("name expected");
			parse_attrs(&sec, 0);
			if (td)
			{
				Sym *s = addsym(nm, S_TYPEDEF);
				s->ty = ty;
			}
			else if (kind() == '(')
			{
				pos++;
				Func *f = 0;
				Sym *s = lookup(nm);
				if (s && s->kind == S_FUNC)
					f = s->fn;
				if (!f)
				{
					f = xcalloc(sizeof *f);
					f->name = nm;
					Sym *ns = addsym(nm, S_FUNC);
					ns->fn = f;
					PUSH(funcs, f);
				}
				f->ret = ty;
				if (sec)
					f->sec = sec;
				Var *params[16];
				int np = 0;
				if (isid("void") && T[pos + 1].k == ')')
					pos += 2;
				else if (!acc(')'))
					for (;;)
					{
						if (np >= 16)
							die("too many parameters");
						Type *pb = declspec(0, 0, 0, 0);
						char *pn = 0;
						Type *pt = declarator(pb, &pn);
						if (pt->kind == TY_ARR)
							pt = ptr_to(pt->base);
						params[np++] = newvar(pn ? pn : "_", pt);
						params[np - 1]->reg = -1;
						if (acc(','))
							continue;
						expect(')');
						break;
					}
				f->np = np;
				f->params = xcalloc(sizeof(Var *) * (np + 1));
				for (int i = 0; i < np; i++)
					f->params[i] = params[i];
				parse_attrs(&sec, 0);
				if (sec)
					f->sec = sec;
				if (kind() == '{')
				{
					push_scope();
					for (int i = 0; i < np; i++)
					{
						Sym *ps = addsym(f->params[i]->name, S_VAR);
						ps->var = f->params[i];
						ps->ty = f->params[i]->ty;
					}
					curfn = f;
					f->body = parse_block();
					f->defined = 1;
					pop_scope();
					break;
				}
			}
			else
			{
				Node *in = 0;
				if (acc('='))
					in = parse_init();
				ty = infer_len(ty, in);
				int md[5] = { 0 }, hasmd = ty->kind == TY_STRUCT && ty->hasmd;
				Type *mdty = 0;
				if (hasmd && legacy_maps)
				{
					for (int i = 0; i < ty->mdn; i++)
					{
						const char *a = ty->mdname[i];
						int v5 = (int)ty->mdval[i];
						if (!strcmp(a, "type"))
							md[0] = v5;
						else if (!strcmp(a, "key") || !strcmp(a, "key_size"))
							md[1] = v5;
						else if (!strcmp(a, "value") || !strcmp(a, "value_size"))
							md[2] = v5;
						else if (!strcmp(a, "max_entries"))
							md[3] = v5;
						else if (!strcmp(a, "map_flags"))
							md[4] = v5;
					}
					ty = array_of(ty_uint, 5);
					if (!sec || !strcmp(sec, ".maps"))
						sec = "maps";
				}
				else if (hasmd)
				{
					mdty = ty;
					ty = array_of(ty_ulong, mdty->mdn ? mdty->mdn : 1);
					sec = ".maps";
					hasmd = 0;
				}
				Var *v = newvar(nm, ty);
				v->mdty = mdty;
				v->global = 1;
				v->sec = sec;
				v->data = xcalloc(ty->size);
				if (in)
				{
					gl_var = v;
					walk_init(ty, in, 0, gleaf);
				}
				if (hasmd)
					for (int i = 0; i < 5; i++)
						for (int j = 0; j < 4; j++)
							v->data[i * 4 + j] = (u8) ((unsigned)md[i] >> (8 * j));
				Sym *s = addsym(nm, S_VAR);
				s->var = v;
				s->ty = ty;
				PUSH(globals, v);
			}
			if (!acc(','))
			{
				expect(';');
				break;
			}
		}
	}
}

/* ======================= code generation ======================= */
typedef struct
{
	uint8_t code, dst, src;
	int16_t off;
	int32_t imm;
} Insn;
static int use_v2;
static Insn *cb;
static int ncb, capcb;
static struct
{
	int idx;
	Var *v;
} *rels;
static int nrels, caprels;
static int *lpos;
static int nlab, caplab;
static struct
{
	int idx, lab;
} *fix;
static int nfix, capfix;
static struct
{
	char *n;
	int lab, def;
} *glab;
static int nglab, capglab, lab_base;
static int stk_cur, stk_max, regmask, inl, ret_lab = -1, brk_lab = -1, cont_lab =
	-1, warned_div, r4_busy;
static Var **pending_owned;
static int n_pending_owned;
/* Set once per function/inline-call right after compute_hot_vars, from
   however many R6-R9 bits the surrounding context has already claimed:
   cur_nfree registers are actually available to THIS function's own (at most
   4) hot candidates. A candidate only claims one if its rank among them is
   below cur_nfree, so when there are more hot candidates than free slots, the 
   ones actually used most win - not whichever happens to be allocated first
   (previously: parameters always before body locals, in declaration order,
   regardless of which was genuinely hotter). When hot_count <= cur_nfree (the
   common case) every hot candidate's rank is already below cur_nfree, so this
   changes nothing then. */
static int cur_nfree;
static int count_free_regs(void)
{
	int n = 0;
	for (int r = 6; r <= 9; r++)
		if (!(regmask & (1 << r)))
			n++;
	return n;
}

static int emit(int code, int dst, int src, int off, i64 imm)
{
	if (ncb == capcb)
	{
		capcb = capcb ? capcb * 2 : 256;
		cb = realloc(cb, capcb * sizeof *cb);
	}
	if (off < -32768 || off > 32767)
		die("stack/struct offset out of range (%d)", off);
	Insn *i = &cb[ncb];
	i->code = (uint8_t) code;
	i->dst = (uint8_t) dst;
	i->src = (uint8_t) src;
	i->off = (int16_t) off;
	i->imm = (int32_t) imm;
	return ncb++;
}

static int newlabel(void)
{
	if (nlab == caplab)
	{
		caplab = caplab ? caplab * 2 : 64;
		lpos = realloc(lpos, caplab * sizeof(int));
	}
	lpos[nlab] = -1;
	return nlab++;
}

static void place(int l)
{
	lpos[l] = ncb;
}

static void jmp_to(int idx, int l)
{
	if (nfix == capfix)
	{
		capfix = capfix ? capfix * 2 : 64;
		fix = realloc(fix, capfix * sizeof *fix);
	}
	fix[nfix].idx = idx;
	fix[nfix].lab = l;
	nfix++;
}

static void jmp(int l)
{
	jmp_to(emit(0x05, 0, 0, 0, 0), l);
}

static void ld_imm64(int dst, i64 v, Var * sym)
{
	int i = emit(0x18, dst, 0, 0, (int32_t) (uint32_t) ((u64) v & 0xffffffffu));
	emit(0, 0, 0, 0, (int32_t) ((u64) v >> 32));
	if (sym)
	{
		if (nrels == caprels)
		{
			caprels = caprels ? caprels * 2 : 16;
			rels = realloc(rels, caprels * sizeof *rels);
		}
		rels[nrels].idx = i;
		rels[nrels].v = sym;
		nrels++;
	}
}

static int fits32(i64 v)
{
	return v >= -2147483648LL && v <= 2147483647LL;
}

static void mov_i(int d, i64 v)
{
	if (fits32(v))
		emit(0xb7, d, 0, 0, v);
	else
		ld_imm64(d, v, 0);
}

static void alu_i(int op, int d, i64 v)
{
	emit(0x07 | op, d, 0, 0, v);
}

static int szb(int n)
{
	return n == 1 ? 0x10 : n == 2 ? 0x08 : n == 4 ? 0x00 : 0x18;
}

static void ldx(int sz, int dst, int base, int off)
{
	emit(0x01 | 0x60 | szb(sz), dst, base, off, 0);
}

static void stx(int sz, int base, int off, int src)
{
	emit(0x03 | 0x60 | szb(sz), base, src, off, 0);
}

static void st_imm(int sz, int base, int off, i64 imm)
{
	emit(0x02 | 0x60 | szb(sz), base, 0, off, imm);
}

static void mov_r(int d, int s)
{
	if (d != s)
		emit(0xbf, d, s, 0, 0);
}

static int alloc_stack(int size, int al)
{
	if (size < 1)
		size = 1;
	stk_cur = (int)align_up(stk_cur + size, al);
	if (stk_cur > stk_max)
		stk_max = stk_cur;
	if (stk_max > 512)
		die("eBPF stack overflow (%d > 512 bytes)", stk_max);
	return -stk_cur;
}

static void norm_reg(int r, Type * t)
{
	if (t->kind == TY_VOID || t->size >= 8)
		return;
	switch (t->size)
	{
	case 4:
		if (t->uns)
			emit(0xbc, r, r, 0, 0);
		else
		{
			alu_i(0x60, r, 32);
			alu_i(0xc0, r, 32);
		}
		break;
	case 2:
		if (t->uns)
			alu_i(0x50, r, 0xffff);
		else
		{
			alu_i(0x60, r, 48);
			alu_i(0xc0, r, 48);
		}
		break;
	case 1:
		if (t->uns)
			alu_i(0x50, r, 0xff);
		else
		{
			alu_i(0x60, r, 56);
			alu_i(0xc0, r, 56);
		}
		break;
	}
}

static void ldx_n(int sz, int dst, int base, int off, Type * t)
{
	ldx(sz, dst, base, off);
	if (t->kind == TY_INT && !t->uns && sz < 8)
		norm_reg(dst, t);
}

static void gen(Node * n);
static void gen_stmt(Node * n);
static void gen_cond(Node * c, int L, int sense);
static Node *strip(Node * n)
{
	while (n->op == N_CAST && n->noop)
		n = n->l;
	return n;
}

static int isreg(Node * n)
{
	n = strip(n);
	return n->op == N_VAR && !n->var->global &&n->var->reg >= 0 && n->val == 0;
}

static int isimm(Node * n, i64 * v)
{
	n = strip(n);
	if (n->op == N_NUM && fits32(n->val))
	{
		*v = n->val;
		return 1;
	}
	return 0;
}

static int regof(Node * n)
{
	return strip(n)->var->reg;
}

static int ptr_static(Node * p, Var ** v, i64 * off);
static int lv_static(Node * l, Var ** v, i64 * off)
{
	switch (l->op)
	{
	case N_VAR:
		if (l->var->reg >= 0)
			return 0;
		*v = l->var;
		*off = l->val;
		return 1;
	case N_MEMBER:
		if (!lv_static(l->l, v, off))
			return 0;
		*off += l->mem->off;
		return 1;
	case N_DEREF:
		return ptr_static(l->l, v, off);
	}
	return 0;
}

static int ptr_static(Node * p, Var ** v, i64 * off)
{
	p = strip(p);
	if (p->op == N_ADDR)
		return lv_static(p->l, v, off);
	if (p->op == N_ADD)
	{
		Node *r = strip(p->r);
		if (r->op == N_NUM && ptr_static(p->l, v, off))
		{
			*off += r->val;
			return 1;
		}
	}
	return 0;
}

static int simple_ptr(Node * p);
static int simple_addr(Node * lv)
{
	Var *v;
	i64 o;
	if (lv_static(lv, &v, &o))
		return 1;
	if (lv->op == N_MEMBER)
		return simple_addr(lv->l);
	if (lv->op == N_DEREF)
		return simple_ptr(lv->l);
	return 0;
}

static int simple_ptr(Node * p)
{
	Node *s = strip(p);
	Var *v;
	i64 o;
	if (isreg(s) || ptr_static(s, &v, &o))
		return 1;
	if (s->op == N_ADDR && simple_addr(s->l))
		return 1;				/* &reg_ptr->field: base register + constant
								   offset */
	if (s->op == N_ADD)
	{
		Node *r = strip(s->r);
		if (r->op == N_NUM)
			return simple_ptr(s->l);
	}
	return 0;
}

static int addr_parts(Node * lv, i64 * off);
static int ptr_parts(Node * p, i64 * off)
{
	Node *s = strip(p);
	Var *v;
	i64 o;
	if (isreg(s))
	{
		*off = 0;
		return regof(s);
	}
	if (ptr_static(s, &v, &o))
	{
		if (v->global)
			die("access to global data is not supported (maps only)");
		*off = v->off + o;
		return 10;
	}
	if (s->op == N_ADDR && simple_addr(s->l))
		return addr_parts(s->l, off);
	if (s->op == N_ADD)
	{
		Node *r = strip(s->r);
		if (r->op == N_NUM)
		{
			int b = ptr_parts(s->l, off);
			*off += r->val;
			return b;
		}
	}
	gen(p);
	*off = 0;
	return 0;
}

static int addr_parts(Node * lv, i64 * off)
{
	Var *v;
	i64 o;
	if (lv_static(lv, &v, &o))
	{
		if (v->global)
			die("access to global data is not supported (maps only)");
		*off = v->off + o;
		return 10;
	}
	if (lv->op == N_MEMBER)
	{
		int b = addr_parts(lv->l, off);
		*off += lv->mem->off;
		return b;
	}
	if (lv->op == N_DEREF)
		return ptr_parts(lv->l, off);
	die("bad lvalue");
	return 0;
}

static void gen_addr(Node * lv)
{
	Var *v;
	i64 o;
	if (lv_static(lv, &v, &o))
	{
		if (v->global)
		{
			if (o)
				die("offset into map symbol unsupported");
			ld_imm64(0, 0, v);
		}
		else
		{
			mov_r(0, 10);
			alu_i(0x00, 0, v->off + o);
		}
		return;
	}
	if (lv->op == N_MEMBER)
	{
		gen_addr(lv->l);
		if (lv->mem->off)
			alu_i(0x00, 0, lv->mem->off);
		return;
	}
	if (lv->op == N_DEREF)
	{
		gen(lv->l);
		return;
	}
	die("bad lvalue");
}

static void gen_load(Node * lv)
{
	Type *t = lv->ty;
	if (t->kind == TY_STRUCT || t->kind == TY_ARR)
		die("aggregate used as a value");
	if (isreg(lv))
	{
		mov_r(0, regof(lv));
		return;
	}
	i64 off;
	int b = addr_parts(lv, &off);
	/* never emit 'rX = *(u64 *)(rX + off)': some 32-bit JITs clobber the base 
	   before reading the high word */
	if (t->size == 8 && b == 0)
	{
		ldx(8, 1, 0, (int)off);
		mov_r(0, 1);
		return;
	}
	ldx_n(t->size, 0, b, (int)off, t);
}

static int alu_code(int nop, Type * t)
{
	switch (nop)
	{
	case N_ADD:
		return 0x00;
	case N_SUB:
		return 0x10;
	case N_MUL:
		return 0x20;
	case N_DIV:
	case N_MOD:
		return nop == N_DIV ? 0x30 : 0x90;
	case N_OR:
		return 0x40;
	case N_AND:
		return 0x50;
	case N_SHL:
		return 0x60;
	case N_SHR:
		return t->uns ? 0x70 : 0xc0;
	case N_XOR:
		return 0xa0;
	}
	die("internal: bad alu op");
	return 0;
}

static void sdivmod(int nop, int dst, int isimm_, i64 v)
{
	/* signed 64-bit div/mod via |a| / |b| and sign fix-up; clobbers r0-r3 */
	if (isimm_)
		mov_i(1, v);
	else
		mov_r(1, (int)v);
	mov_r(0, dst);
	mov_r(2, 0);
	alu_i(0xc0, 2, 63);
	mov_r(3, 1);
	alu_i(0xc0, 3, 63);
	emit(0x0f | 0xa0, 0, 2, 0, 0);
	emit(0x0f | 0x10, 0, 2, 0, 0);	/* r0 ^= r2; r0 -= r2 */
	emit(0x0f | 0xa0, 1, 3, 0, 0);
	emit(0x0f | 0x10, 1, 3, 0, 0);	/* r1 ^= r3; r1 -= r3 */
	emit(0x0f | (nop == N_DIV ? 0x30 : 0x90), 0, 1, 0, 0);
	if (nop == N_DIV)
		emit(0x0f | 0xa0, 2, 3, 0, 0);	/* r2 ^= r3: result sign */
	emit(0x0f | 0xa0, 0, 2, 0, 0);
	emit(0x0f | 0x10, 0, 2, 0, 0);
	mov_r(dst, 0);
}

/* n if v is an exact power of two >= 2 (so a shift by n is equivalent), else
   -1 */
static int pow2_log(i64 v)
{
	if (v < 2)
		return -1;
	u64 u = (u64) v;
	if (u & (u - 1))
		return -1;
	int n = 0;
	while (u > 1)
	{
		u >>= 1;
		n++;
	}
	return n;
}

static void signed_divmod_pow2(int ismod, int dst, int n)
{
	/* dst already holds the (sign-extended 64-bit) dividend, evaluated
	   exactly once by the caller before alu_op was reached - this operates
	   purely on registers, so it's safe even if the dividend expression has
	   side effects. Same idiom gcc/clang use for signed division by a
	   constant power of two: adding the (2^n - 1) bias only when negative
	   turns the plain arithmetic shift's floor-division into C's
	   truncate-toward-zero division. Uses r1 as scratch, same as sdivmod
	   (same r1-r3-free invariant applies: only called here with isimm_ true,
	   i.e. the divisor is a literal, which no caller ever holds live in r1-r3 
	   across - see sdivmod's own comment/usage for why that's guaranteed).
	   About half the instructions of the general sdivmod path, and it leaves
	   r2/r3 untouched. */
	mov_r(1, dst);
	alu_i(0xc0, 1, 63);
	alu_i(0x70, 1, 64 - n);
	emit(0x0f, 1, dst, 0, 0);
	alu_i(0xc0, 1, n);
	if (ismod)
	{
		alu_i(0x60, 1, n);
		emit(0x0f | 0x10, dst, 1, 0, 0);
	}
	else
		mov_r(dst, 1);
}

static void alu_op(int nop, int dst, int isimm_, i64 v, Type * t)
{
	if (isimm_)
	{
		int n = pow2_log(v);
		if (nop == N_MUL && n > 0)
		{
			alu_i(0x60, dst, n);
			return;
		}						/* x * 2^n -> x << n */
		if ((nop == N_DIV || nop == N_MOD) && n > 0)
		{
			if (t->uns)
			{
				alu_i(nop == N_DIV ? 0x70 : 0x50, dst, nop == N_DIV ? n : v - 1);
				return;
			}					/* x/2^n -> x>>n; x%2^n -> x&(2^n-1) */
			signed_divmod_pow2(nop == N_MOD, dst, n);
			return;
		}
	}
	if ((nop == N_DIV || nop == N_MOD) && !t->uns)
	{
		sdivmod(nop, dst, isimm_, v);
		return;
	}
	int op = alu_code(nop, t);
	if (isimm_)
		emit(0x07 | op, dst, 0, 0, v);
	else
		emit(0x07 | op | 0x08, dst, (int)v, 0, 0);
}

static void post_norm(int R, int aop, Type * lt, Type * ct)
{
	int need = aop == N_ADD || aop == N_SUB || aop == N_MUL || aop == N_SHL;
	Type *t2 = ct;
	if (need)
	{
		if (lt->kind == TY_INT && lt->size <= ct->size && lt->size < 8)
			t2 = lt;
		norm_reg(R, t2);
	}
	if (t2 != lt && needs_norm(t2, lt))
		norm_reg(R, lt);
}

static void memcpy_emit(int db, i64 doff, int sb, i64 soff, int n, int al)
{
	for (int i = 0; i < n;)
	{
		int c = al > 8 ? 8 : al;
		while (c > 1 && (c > n - i || (i % c)))
			c /= 2;
		ldx(c, 0, sb, (int)(soff + i));
		stx(c, db, (int)(doff + i), 0);
		i += c;
	}
}

static void zero_emit(int base, i64 off, int n, int al)
{
	for (int i = 0; i < n;)
	{
		int c = al > 8 ? 8 : al;
		while (c > 1 && (c > n - i || ((off + i) % c)))
			c /= 2;
		st_imm(c, base, (int)(off + i), 0);
		i += c;
	}
}

static void gen_structcopy(Node * lv, Node * rs)
{
	if (!islv(rs))
		die("unsupported struct assignment source");
	/* an address that must survive a later gen() call (because it isn't
	   "simple") is kept in r4/r5 instead of spilled to the stack: one mov
	   instead of a store+reload pair, and r4/r5 are never touched by anything 
	   else that could still be live across a nested call (see
	   sdivmod/r4_busy). */
	int sd = simple_addr(lv), ss = simple_addr(rs), ob = r4_busy;
	i64 doff = 0, soff = 0;
	int db, sb;
	if (!sd)
	{
		gen_addr(lv);
		mov_r(4, 0);
		r4_busy = 1;
	}
	if (!ss)
	{
		gen_addr(rs);
		mov_r(5, 0);
	}
	r4_busy = ob;
	if (sd)
		db = addr_parts(lv, &doff);
	else
		db = 4;
	if (ss)
		sb = addr_parts(rs, &soff);
	else
		sb = 5;
	memcpy_emit(db, doff, sb, soff, lv->ty->size, lv->ty->align);
}

static void fix_post(Node * n)
{
	if (!n->post)
		return;
	alu_i(n->aop == N_ADD ? 0x10 : 0x00, 0, strip(n->r)->val);
	norm_reg(0, n->l->ty);
}

static void gen_assign(Node * n, int disc)
{
	Node *lv = n->l, *rs = n->r;
	Type *lt = lv->ty, *ct = n->cty;
	int aop = n->aop;
	i64 v;
	if (lt->kind == TY_STRUCT)
	{
		gen_structcopy(lv, rs);
		return;
	}
	if (isreg(lv))
	{
		int R = regof(lv);
		if (!aop)
		{
			if (isimm(rs, &v))
				mov_i(R, v);
			else if (isreg(rs))
				mov_r(R, regof(rs));
			else
			{
				gen(rs);
				mov_r(R, 0);
			}
		}
		else
		{
			int rimm = isimm(rs, &v), rr = -1;
			if (!rimm)
			{
				if (isreg(rs))
					rr = regof(rs);
				else
				{
					gen(rs);
					rr = 0;
				}
			}
			if (needs_norm(lt, ct))
				norm_reg(R, ct);
			alu_op(aop, R, rimm, rimm ? v : rr, ct);
			post_norm(R, aop, lt, ct);
		}
		if (!disc)
		{
			mov_r(0, R);
			fix_post(n);
		}
		return;
	}
	int simple = simple_addr(lv), sz = lt->size, base, ob = r4_busy;
	i64 off = 0;
	if (!simple)
	{
		gen_addr(lv);
		mov_r(4, 0);
		r4_busy = 1;
	}
	int rimm = isimm(rs, &v);
	if (!aop)
	{
		if (!rimm)
			gen(rs);
		r4_busy = ob;
		base = simple ? addr_parts(lv, &off) : 4;
		if (rimm)
		{
			st_imm(sz, base, (int)off, v);
			if (!disc)
				mov_i(0, v);
		}
		else
			stx(sz, base, (int)off, 0);
	}
	else
	{
		if (!rimm)
		{
			gen(rs);
			mov_r(1, 0);
		}
		r4_busy = ob;
		base = simple ? addr_parts(lv, &off) : 4;
		ldx_n(sz, 0, base, (int)off, lt);
		if (needs_norm(lt, ct))
			norm_reg(0, ct);
		alu_op(aop, 0, rimm, rimm ? v : 1, ct);
		post_norm(0, aop, lt, ct);
		stx(sz, base, (int)off, 0);
		if (!disc)
			fix_post(n);
	}
}

static int direct(Node * a)
{
	i64 v;
	Var *g;
	i64 o;
	return isimm(a, &v) || isreg(a) || ptr_static(a, &g, &o);
}

static void load_arg(int r, Node * a, int T)
{
	i64 v, o;
	Var *g;
	if (T)
	{
		ldx(8, r, 10, T);
		return;
	}
	if (isimm(a, &v))
	{
		mov_i(r, v);
		return;
	}
	if (isreg(a))
	{
		mov_r(r, regof(a));
		return;
	}
	if (ptr_static(a, &g, &o))
	{
		if (g->global)
		{
			if (o)
				die("offset into map symbol unsupported");
			ld_imm64(r, 0, g);
		}
		else
		{
			mov_r(r, 10);
			alu_i(0x00, r, g->off + o);
		}
		return;
	}
	die("internal: bad direct arg");
}

static void call_helper(int hid, Node ** a, int na)
{
	if (na > 5)
		die("helper calls take at most 5 arguments");
	int T[5] = { 0 }, save = stk_cur;
	for (int i = 0; i < na; i++)
		if (!direct(a[i]))
		{
			gen(a[i]);
			T[i] = alloc_stack(8, 8);
			stx(8, 10, T[i], 0);
		}
	for (int i = 0; i < na; i++)
		load_arg(i + 1, a[i], T[i]);
	emit(0x85, 0, 0, 0, hid);
	stk_cur = save;
}

static void compute_hot_vars(Func * f);
static void gen_inline(Node * n)
{
	Func *f = n->fn;
	if (!f->defined)
		die("function '%s' has no body (non-SEC functions are inlined)", f->name);
	if (inl >= 8)
		die("inline nesting too deep / recursion in '%s'", f->name);
	compute_hot_vars(f);
	int save = stk_cur, srm = regmask, snf = cur_nfree;
	cur_nfree = count_free_regs();	/* what the call site left free, for THIS
									   callee's own candidates */
	inl++;
	for (int i = 0; i < f->np; i++)
	{
		Var *p = f->params[i];
		Type *pt = p->ty;
		int r = -1;
		if (p->hot && p->hotrank < cur_nfree && (pt->kind == TY_INT || pt->kind == TY_PTR)
			&& !p->addr)
			for (int rr = 6; rr <= 9; rr++)
				if (!(regmask & (1 << rr)))
				{
					r = rr;
					break;
				}
		if (r >= 0)
		{
			regmask |= 1 << r;
			p->reg = r;
			gen(n->args[i]);
			mov_r(r, 0);
		}
		else
		{
			p->reg = -1;
			int off = alloc_stack(pt->size, 8);
			gen(n->args[i]);
			stx(pt->size, 10, off, 0);
			p->off = off;
		}
	}
	int ol = ret_lab, ob = brk_lab, oc = cont_lab, olb = lab_base;
	ret_lab = newlabel();
	brk_lab = cont_lab = -1;
	lab_base = nglab;
	Var *inl_owned[16];
	int n_io = 0;
	for (int i = 0; i < f->np; i++)
		if (f->params[i]->reg >= 6 && f->params[i]->reg <= 9)
			inl_owned[n_io++] = f->params[i];
	pending_owned = inl_owned;
	n_pending_owned = n_io;
	gen_stmt(f->body);
	mov_i(0, 0);
	place(ret_lab);
	ret_lab = ol;
	lab_base = olb;
	brk_lab = ob;
	cont_lab = oc;
	inl--;
	stk_cur = save;
	regmask = srm;
	cur_nfree = snf;
}

static int chunk_by(int n)
{
	return n % 8 == 0 ? 8 : n % 4 == 0 ? 4 : n % 2 == 0 ? 2 : 1;
}

static void gen_builtin(Node * n)
{
	if (n->bi == BI_PRINTK)
	{
		Node *f = n->args[0];
		int len = (int)f->val + 1, save = stk_cur;
		Var *tv = xcalloc(sizeof *tv);
		tv->ty = array_of(ty_char, len);
		tv->reg = -1;
		tv->off = alloc_stack(len, 8);
		for (int i = 0; i < len;)
		{
			int c = (i % 4 == 0 && i + 4 <= len) ? 4 : (i % 2 == 0 && i + 2 <= len) ? 2 : 1;
			i64 v = 0;
			for (int j = c - 1; j >= 0; j--)
				v = (v << 8) | (u8) f->str[i + j];
			st_imm(c, 10, tv->off + i, (int32_t) v);
			i += c;
		}
		Node *vn = newn(N_VAR, tv->ty);
		vn->var = tv;
		Node *a0 = newn(N_ADDR, ptr_to(ty_char));
		a0->l = vn;
		Node *av[5];
		av[0] = a0;
		av[1] = num(len, ty_long);
		int na = 2;
		for (int i = 1; i < n->nargs; i++)
			av[na++] = n->args[i];
		call_helper(6, av, na);
		stk_cur = save;
		return;
	}
	if (n->bi == BI_XADD)
	{
		int sp = simple_ptr(n->args[0]), ob = r4_busy;
		i64 off = 0;
		int base;
		if (!sp)
		{
			gen(n->args[0]);
			mov_r(4, 0);
			r4_busy = 1;
		}
		gen(n->args[1]);
		mov_r(1, 0);
		r4_busy = ob;
		base = sp ? ptr_parts(n->args[0], &off) : 4;
		emit(0x03 | 0xc0 | szb((int)n->val), base, 1, (int)off, 0);
		return;
	}
	if (n->bi == BI_BSWAP)
	{
		gen(n->args[0]);
		emit(0xdc, 0, 0, 0, n->val);
		return;
	}
	/* memset / memcpy with constant size */
	int sz = (int)n->val;
	Node *d = n->args[0], *s = n->bi == BI_MEMCPY ? n->args[1] : 0;
	int sd = simple_ptr(d), ss = s ? simple_ptr(s) : 1, ob = r4_busy;
	i64 doff = 0, soff = 0;
	int db, sb = 0;
	if (!sd)
	{
		gen(d);
		mov_r(4, 0);
		r4_busy = 1;
	}
	if (s && !ss)
	{
		gen(s);
		mov_r(5, 0);
	}
	r4_busy = ob;
	if (sd)
		db = ptr_parts(d, &doff);
	else
		db = 4;
	if (s)
	{
		if (ss)
			sb = ptr_parts(s, &soff);
		else
			sb = 5;
	}
	if (n->bi == BI_MEMCPY)
		memcpy_emit(db, doff, sb, soff, sz, chunk_by(sz));
	else
	{
		int b = n->aop & 0xff, al = chunk_by(sz);
		if (b != 0 && b != 0xff && al > 4)
			al = 4;
		for (int i = 0; i < sz;)
		{
			int c = al;
			while (c > 1 && c > sz - i)
				c /= 2;
			i64 imm = 0;
			if (c == 8)
				imm = b ? -1 : 0;
			else
				for (int j = 0; j < c; j++)
					imm |= (i64) b << (8 * j);
			st_imm(c, db, (int)(doff + i), (int32_t) imm);
			i += c;
		}
	}
}

static void gen_call(Node * n)
{
	if (n->bi)
	{
		gen_builtin(n);
		return;
	}
	if (n->fn)
	{
		gen_inline(n);
		return;
	}
	call_helper(n->hid, n->args, n->nargs);
	if (n->hret == 'w')
		norm_reg(0, ty_uint);
	else if (!n->hret && n->ty->kind != TY_VOID && n->ty->size < 8)
		norm_reg(0, n->ty);		/* user-declared helper with a narrow return
								   type */
}

static int negop(int op)
{
	switch (op)
	{
	case N_EQ:
		return N_NE;
	case N_NE:
		return N_EQ;
	case N_LT:
		return N_GE;
	case N_GE:
		return N_LT;
	case N_LE:
		return N_GT;
	default:
		return N_LE;
	}
}

static int swapop(int op)
{
	switch (op)
	{
	case N_LT:
		return N_GT;
	case N_GT:
		return N_LT;
	case N_LE:
		return N_GE;
	case N_GE:
		return N_LE;
	default:
		return op;
	}
}

static void jcc_emit(int op, int uns, int ra, int bimm, i64 b, int L)
{
	int code;
	if (op == N_LT || op == N_LE)
	{
		if (use_v2)
			code = op == N_LT ? (uns ? 0xa0 : 0xc0) : (uns ? 0xb0 : 0xd0);
		else if (bimm)
		{
			int sk = newlabel();
			jcc_emit(op == N_LT ? N_GE : N_GT, uns, ra, 1, b, sk);
			jmp(L);
			place(sk);
			return;
		}
		else
		{
			code = op == N_LT ? (uns ? 0x20 : 0x60) : (uns ? 0x30 : 0x70);
			jmp_to(emit(0x05 | code | 0x08, (int)b, ra, 0, 0), L);
			return;
		}
	}
	else
		switch (op)
		{
		case N_EQ:
			code = 0x10;
			break;
		case N_NE:
			code = 0x50;
			break;
		case N_GT:
			code = uns ? 0x20 : 0x60;
			break;
		default:
			code = uns ? 0x30 : 0x70;
			break;
		}
	if (bimm)
		jmp_to(emit(0x05 | code, ra, 0, 0, b), L);
	else
		jmp_to(emit(0x05 | code | 0x08, ra, (int)b, 0, 0), L);
}

static void gen_cmp(Node * c, int L, int sense)
{
	int op = sense ? c->op : negop(c->op), uns = c->cty->uns;
	Node *a = c->l, *b = c->r;
	i64 v;
	if (isimm(a, &v) && !isimm(b, &v))
	{
		Node *t = a;
		a = b;
		b = t;
		op = swapop(op);
	}
	int ra, bimm = 0, rb = 0;
	if (isimm(b, &v))
	{
		bimm = 1;
		if (isreg(a))
			ra = regof(a);
		else
		{
			gen(a);
			ra = 0;
		}
	}
	else if (isreg(b))
	{
		rb = regof(b);
		if (isreg(a))
			ra = regof(a);
		else
		{
			gen(a);
			ra = 0;
		}
	}
	else if (!r4_busy)
	{
		r4_busy = 1;
		gen(a);
		mov_r(4, 0);
		gen(b);
		r4_busy = 0;
		ra = 4;
		rb = 0;
	}
	else
	{
		int sv = stk_cur;
		gen(a);
		int T = alloc_stack(8, 8);
		stx(8, 10, T, 0);
		gen(b);
		mov_r(5, 0);
		ldx(8, 0, 10, T);
		stk_cur = sv;
		ra = 0;
		rb = 5;
	}
	jcc_emit(op, uns, ra, bimm, bimm ? v : rb, L);
}

static void gen_cond(Node * c, int L, int sense)
{
	switch (c->op)
	{
	case N_NUM:
		if ((c->val != 0) == sense)
			jmp(L);
		return;
	case N_NOT:
		gen_cond(c->l, L, !sense);
		return;
	case N_LAND:
		if (sense)
		{
			int sk = newlabel();
			gen_cond(c->l, sk, 0);
			gen_cond(c->r, L, 1);
			place(sk);
		}
		else
		{
			gen_cond(c->l, L, 0);
			gen_cond(c->r, L, 0);
		}
		return;
	case N_LOR:
		if (sense)
		{
			gen_cond(c->l, L, 1);
			gen_cond(c->r, L, 1);
		}
		else
		{
			int sk = newlabel();
			gen_cond(c->l, sk, 1);
			gen_cond(c->r, L, 0);
			place(sk);
		}
		return;
	case N_EQ:
	case N_NE:
	case N_LT:
	case N_LE:
	case N_GT:
	case N_GE:
		gen_cmp(c, L, sense);
		return;
	}
	int r;
	if (isreg(c))
		r = regof(c);
	else
	{
		gen(c);
		r = 0;
	}
	jmp_to(emit(0x05 | (sense ? 0x50 : 0x10), r, 0, 0, 0), L);
}

static void gen_discard(Node * e)
{
	if (e->op == N_ASSIGN)
		gen_assign(e, 1);
	else
		gen(e);
}

static void gen(Node * n)
{
	i64 v;
	switch (n->op)
	{
	case N_NUM:
		mov_i(0, n->val);
		break;
	case N_STR:
		die("string literals are only supported in bpf_printk and char array initializers");
	case N_VAR:
	case N_DEREF:
	case N_MEMBER:
		gen_load(n);
		break;
	case N_ADDR:
		gen_addr(n->l);
		break;
	case N_CAST:
		gen(n->l);
		if (!n->noop && n->ty->kind != TY_VOID)
			norm_reg(0, n->ty);
		break;
	case N_ADD:
	case N_SUB:
	case N_MUL:
	case N_DIV:
	case N_MOD:
	case N_AND:
	case N_OR:
	case N_XOR:
	case N_SHL:
	case N_SHR:
		{
			Node *a = n->l, *b = n->r;
			if ((n->op == N_ADD || n->op == N_MUL || n->op == N_AND || n->op == N_OR
				 || n->op == N_XOR) && isimm(a, &v) && !isimm(b, &v))
			{
				Node *t = a;
				a = b;
				b = t;
			}
			if (isimm(b, &v))
			{
				gen(a);
				alu_op(n->op, 0, 1, v, n->ty);
			}
			else if (isreg(b))
			{
				gen(a);
				alu_op(n->op, 0, 0, regof(b), n->ty);
			}
			else if (!r4_busy)
			{
				/* keep 'a' in r4 across gen(b) instead of spilling to the
				   stack: same instruction count, but register-register movs
				   are faster than a stack round trip on real hardware. r4/r5
				   (not r1-r3) because signed div/mod (sdivmod)
				   unconditionally clobbers r0-r3 as scratch. */
				r4_busy = 1;
				gen(a);
				mov_r(4, 0);
				gen(b);
				alu_op(n->op, 4, 0, 0, n->ty);
				mov_r(0, 4);
				r4_busy = 0;
			}
			else
			{
				/* nested inside another such temporary (r4 already held by an 
				   outer expression): fall back to the stack, but combine via
				   r5 so the outer's r4 is left untouched */
				int sv = stk_cur;
				gen(a);
				int T = alloc_stack(8, 8);
				stx(8, 10, T, 0);
				gen(b);
				mov_r(5, 0);
				ldx(8, 0, 10, T);
				alu_op(n->op, 0, 0, 5, n->ty);
				stk_cur = sv;
			}
			if (n->op == N_ADD || n->op == N_SUB || n->op == N_MUL || n->op == N_SHL)
				norm_reg(0, n->ty);
			break;
		}
	case N_NEG:
		gen(n->l);
		emit(0x87, 0, 0, 0, 0);
		norm_reg(0, n->ty);
		break;
	case N_BNOT:
		gen(n->l);
		alu_i(0xa0, 0, -1);
		norm_reg(0, n->ty);
		break;
	case N_EQ:
	case N_NE:
	case N_LT:
	case N_LE:
	case N_GT:
	case N_GE:
	case N_LAND:
	case N_LOR:
	case N_NOT:
		{
			int Lt = newlabel(), Le = newlabel();
			gen_cond(n, Lt, 1);
			mov_i(0, 0);
			jmp(Le);
			place(Lt);
			mov_i(0, 1);
			place(Le);
			break;
		}
	case N_COND:
		{
			int Lf = newlabel(), Le = newlabel();
			gen_cond(n->c, Lf, 0);
			gen(n->l);
			jmp(Le);
			place(Lf);
			gen(n->r);
			place(Le);
			break;
		}
	case N_COMMA:
		gen_discard(n->l);
		gen(n->r);
		break;
	case N_ASSIGN:
		gen_assign(n, 0);
		break;
	case N_CALL:
		gen_call(n);
		break;
	default:
		die("internal: cannot generate expression (op %d)", n->op);
	}
}

/* usage-weighted register allocation: a prepass (compute_hot_vars) counts how 
   many times each local is referenced, weighting loop bodies (actual runtime
   repeats matter more than textual position), and marks the top 4 eligible
   locals of the entry function as "hot". Only hot locals compete for R6-R9
   here; this keeps the exact same scope-based regmask save/restore as before
   (see N_BLOCK in gen_stmt), so a hot local can still lose out to another hot 
   local with an overlapping live range - it just no longer loses to a
   rarely-used local purely because that one happened to be declared first in
   the source. */
static void count_uses(Node * n, i64 w)
{
	if (!n)
		return;
	if (n->op == N_VAR)
	{
		n->var->usecount += w;
		return;
	}
	if (n->op == N_FOR || n->op == N_WHILE || n->op == N_DO)
	{
		i64 m = n->unroll ? (n->unroll > 0 ? n->unroll : 16) : 8;
		i64 lw = w * m;
		if (lw > w && lw / m != w)
			lw = w * 4096;		/* overflow guard */
		if (n->op == N_FOR)
			count_uses(n->l, w);
		count_uses(n->c, lw);
		count_uses(n->body, lw);
		if (n->op == N_FOR)
			count_uses(n->r, lw);
		return;
	}
	count_uses(n->l, w);
	count_uses(n->r, w);
	count_uses(n->c, w);
	count_uses(n->body, w);
	for (int i = 0; i < n->nargs; i++)
		count_uses(n->args[i], w);
	count_uses(n->next, w);
}

static void collect_decls(Node * n, Var ** list, int *nl, int cap)
{
	if (!n || *nl >= cap)
		return;
	if (n->op == N_DECL)
		list[(*nl)++] = n->var;
	collect_decls(n->l, list, nl, cap);
	collect_decls(n->r, list, nl, cap);
	collect_decls(n->c, list, nl, cap);
	collect_decls(n->body, list, nl, cap);
	for (int i = 0; i < n->nargs; i++)
		collect_decls(n->args[i], list, nl, cap);
	collect_decls(n->next, list, nl, cap);
}

typedef struct
{
	Var *v;
	int idx;
} HotCand;
static int cmp_hotcand(const void *a, const void *b)
{
	const HotCand *x = a, *y = b;
	if (x->v->usecount != y->v->usecount)
		return y->v->usecount > x->v->usecount ? 1 : -1;
	return x->idx - y->idx;		/* ties: earlier declaration wins, for
								   determinism */
}

static void compute_hot_vars(Func * f)
{
	if (f->hot_computed)
		return;
	f->hot_computed = 1;
	enum
	{ CAP = 1024 };
	Var **cand = xcalloc(sizeof(Var *) * CAP);
	int nc = 0;
	for (int i = 0; i < f->np; i++)
		if ((f->params[i]->ty->kind == TY_INT || f->params[i]->ty->kind == TY_PTR)
			&& !f->params[i]->addr)
			cand[nc++] = f->params[i];
	collect_decls(f->body, cand, &nc, CAP);
	count_uses(f->body, 1);
	HotCand *elig = xcalloc(sizeof(HotCand) * nc);
	int ne = 0;
	for (int i = 0; i < nc; i++)
	{
		Var *v = cand[i];
		if ((v->ty->kind == TY_INT || v->ty->kind == TY_PTR) && !v->addr)
		{
			elig[ne].v = v;
			elig[ne].idx = i;
			ne++;
		}
	}
	qsort(elig, ne, sizeof *elig, cmp_hotcand);
	f->hot_count = ne < 4 ? ne : 4;
	for (int i = 0; i < ne && i < 4; i++)
	{
		elig[i].v->hot = 1;
		elig[i].v->hotrank = i;
	}
}

static void gen_decl(Var * v)
{
	Type *t = v->ty;
	if (v->hot && v->hotrank < cur_nfree && (t->kind == TY_INT || t->kind == TY_PTR) && !v->addr)
	{
		for (int r = 6; r <= 9; r++)
			if (!(regmask & (1 << r)))
			{
				regmask |= 1 << r;
				v->reg = r;
				return;
			}
	}
	v->reg = -1;
	v->off = alloc_stack(t->size, 8);
}

static int golab(const char *nm, int def)
{
	for (int i = lab_base; i < nglab; i++)
		if (!strcmp(glab[i].n, nm))
		{
			if (def)
			{
				if (glab[i].def)
					die("duplicate label '%s'", nm);
				glab[i].def = 1;
			}
			return glab[i].lab;
		}
	if (nglab == capglab)
	{
		capglab = capglab ? capglab * 2 : 16;
		glab = realloc(glab, capglab * sizeof *glab);
	}
	glab[nglab].n = (char *)nm;
	glab[nglab].lab = newlabel();
	glab[nglab].def = def;
	return glab[nglab++].lab;
}

/* Per-block early register release. A hot variable's register is normally
   held for its whole enclosing block (freed only on block exit, via the
   regmask save/restore above); this lets a variable owned by THIS block give
   its register back as soon as its LAST reference within this block's own
   flat statement sequence has been generated, so a LATER statement -
   including a later inlined call's own hot locals/params - can claim it
   instead. Indexing is per flat statement, not per instruction: a real
   (non-unrolled) loop or an if/else is one statement from this accounting's
   point of view, so nothing is freed partway through one, only once it has
   been fully generated - which is enough, since by the time generated code
   reaches whatever comes after such a statement, that statement's own
   execution (however many times a loop inside it actually runs) is already
   behind it. A variable owned by an ENCLOSING block is left alone here even
   if this is its last mention; freeing it remains that enclosing block's own
   job, when gen_block_stmts runs for it in turn - never touching a register
   this block didn't allocate keeps this strictly additive over the existing
   scope-based save/restore, not a replacement for it. */
/* Last-use positions are tracked purely locally to ONE gen_block_stmts call - 
   in on-stack arrays keyed to that call's own "owned" set - never on the Var
   itself. A Var has no spare field safe for this to live in across nesting
   levels: an earlier attempt stored it directly on Var, and a NESTED block's
   own (unrelated) local numbering silently overwrote what an ENCLOSING block
   had just computed for the very same variable, freeing it too early.
   Confined to local arrays, a nested call simply has no way to disturb data
   that belongs to a call further out - it only ever touches its OWN owned
   set, to which a not-locally-declared variable such as an enclosing ctx can
   never belong. */
static void mark_own_last_use(Node * n, int idx, Var ** owned, int nowned, int *last)
{
	if (!n)
		return;
	if (n->op == N_VAR)
	{
		for (int i = 0; i < nowned; i++)
			if (owned[i] == n->var)
			{
				last[i] = idx;
				return;
			}
		return;
	}
	/* a nested block's own statement chain all counts as this same idx - from 
	   the enclosing block's point of view, the whole nested block is one
	   statement; walking only its first statement (the bug this fixes) missed 
	   every reference after that in the block, such as inside a real loop's
	   braced body. */
	if (n->op == N_BLOCK)
	{
		for (Node * s = n->body; s; s = s->next)
			mark_own_last_use(s, idx, owned, nowned, last);
		return;
	}
	mark_own_last_use(n->l, idx, owned, nowned, last);
	mark_own_last_use(n->r, idx, owned, nowned, last);
	mark_own_last_use(n->c, idx, owned, nowned, last);
	mark_own_last_use(n->body, idx, owned, nowned, last);
	for (int i = 0; i < n->nargs; i++)
		mark_own_last_use(n->args[i], idx, owned, nowned, last);
}

static void gen_block_stmts(Node * body)
{
	enum
	{ MAXOWN = 64 };
	Var *owned[MAXOWN];
	int nowned = 0;
	for (int i = 0; i < n_pending_owned && nowned < MAXOWN; i++)
		owned[nowned++] = pending_owned[i];
	n_pending_owned = 0;
	for (Node * s = body; s; s = s->next)
		if (s->op == N_DECL && nowned < MAXOWN)
			owned[nowned++] = s->var;
	int last[MAXOWN], freed[MAXOWN];
	for (int i = 0; i < nowned; i++)
	{
		last[i] = -1;
		freed[i] = 0;
	}
	int idx = 0;
	for (Node * s = body; s; s = s->next, idx++)
		mark_own_last_use(s, idx, owned, nowned, last);
	int k = 0;
	for (Node * s = body; s; s = s->next, k++)
	{
		gen_stmt(s);
		/* freed[] makes each entry act at most once: v->reg itself is not
		   touched on release, so once its slot is handed to a later variable, 
		   this entry's own (now-stale) reg==that-same-number must never match 
		   again - without the flag, it would keep re-clearing a bit a later
		   owner is actively using. */
		for (int i = 0; i < nowned; i++)
		{
			Var *v = owned[i];
			if (!freed[i] && v->reg >= 6 && v->reg <= 9 && last[i] <= k)
			{
				regmask &= ~(1 << v->reg);
				freed[i] = 1;
			}
		}
	}
}

static void gen_stmt(Node * n)
{
	if (!n)
		return;
	switch (n->op)
	{
	case N_NOP:
		break;
	case N_BLOCK:
		{
			int sm = regmask, sc = stk_cur;
			gen_block_stmts(n->body);
			if (!n->post)
			{
				regmask = sm;
				stk_cur = sc;
			}
			break;
		}
	case N_GOTO:
		jmp(golab(n->str, 0));
		break;
	case N_LABEL:
		place(golab(n->str, 1));
		gen_stmt(n->body);
		break;
	case N_CASE:
		place(n->hid);
		gen_stmt(n->body);
		break;
	case N_SWITCH:
		{
			int Lend = newlabel(), ob = brk_lab;
			for (Node * c = n->cl; c; c = c->cnext)
				c->hid = newlabel();
			if (n->r)
				n->r->hid = newlabel();
			gen(n->c);
			for (Node * c = n->cl; c; c = c->cnext)
			{
				i64 v = normv(c->val, n->cty);
				if (fits32(v))
					jcc_emit(N_EQ, 1, 0, 1, v, c->hid);
				else
				{
					mov_i(1, v);
					jcc_emit(N_EQ, 1, 0, 0, 1, c->hid);
				}
			}
			jmp(n->r ? n->r->hid : Lend);
			brk_lab = Lend;
			gen_stmt(n->body);
			place(Lend);
			brk_lab = ob;
			break;
		}
	case N_DECL:
		gen_decl(n->var);
		break;
	case N_ZERO:
		zero_emit(10, n->var->off, n->var->ty->size, 8);
		break;
	case N_EXPR:
		gen_discard(n->l);
		break;
	case N_IF:
		{
			int Le = newlabel();
			gen_cond(n->c, Le, 0);
			gen_stmt(n->l);
			if (n->r)
			{
				int Lx = newlabel();
				jmp(Lx);
				place(Le);
				gen_stmt(n->r);
				place(Lx);
			}
			else
				place(Le);
			break;
		}
	case N_WHILE:
	case N_FOR:
		{
			int sm = regmask, sc = stk_cur, ob = brk_lab, oc = cont_lab, Lend = newlabel();
			for (Node * s = n->op == N_FOR ? n->l : 0; s; s = s->next)
				gen_stmt(s);
			if (n->unroll)
			{
				int K = n->unroll > 0 ? n->unroll : 16;
				for (int k = 0; k < K; k++)
				{
					int Lc = newlabel();
					brk_lab = Lend;
					cont_lab = Lc;
					if (n->c)
						gen_cond(n->c, Lend, 0);
					gen_stmt(n->body);
					place(Lc);
					if (n->op == N_FOR && n->r)
						gen_discard(n->r);
				}
				place(Lend);
			}
			else
			{
				int Ltop = newlabel(), Lc = newlabel();
				brk_lab = Lend;
				cont_lab = Lc;
				place(Ltop);
				if (n->c)
					gen_cond(n->c, Lend, 0);
				gen_stmt(n->body);
				place(Lc);
				if (n->op == N_FOR && n->r)
					gen_discard(n->r);
				jmp(Ltop);
				place(Lend);
			}
			brk_lab = ob;
			cont_lab = oc;
			regmask = sm;
			stk_cur = sc;
			break;
		}
	case N_DO:
		{
			int ob = brk_lab, oc = cont_lab, Ltop = newlabel(), Lc = newlabel(), Lend = newlabel();
			brk_lab = Lend;
			cont_lab = Lc;
			place(Ltop);
			gen_stmt(n->body);
			place(Lc);
			gen_cond(n->c, Ltop, 1);
			place(Lend);
			brk_lab = ob;
			cont_lab = oc;
			break;
		}
	case N_RETURN:
		if (n->l)
			gen(n->l);
		else
			mov_i(0, 0);
		if (inl)
			jmp(ret_lab);
		else
			emit(0x95, 0, 0, 0, 0);
		break;
	case N_BREAK:
		if (brk_lab < 0)
			die("break outside loop");
		jmp(brk_lab);
		break;
	case N_CONT:
		if (cont_lab < 0)
			die("continue outside loop");
		jmp(cont_lab);
		break;
	default:
		die("internal: bad statement %d", n->op);
	}
}

typedef struct
{
	Func *f;
	Insn *c;
	int n;
	int *ridx;
	Var **rvar;
	int nrel;
} Prog;
static VEC(Prog) progs;

/* ---- final instruction-stream cleanup (runs once per program, on the flat
   instruction array) ---- keep[i] == 0 means "removed". A removed instruction 
   is simply skipped: control that would have reached it falls to the next
   kept one, and a jump whose label pointed at it lands there too. */
	 static int nl(const u8 * keep, int i)
{
	while (i < ncb && !keep[i])
		i++;
	return i;
}

static int is_cond_jmp(int code)
{
	return (code & 7) == 5 && (code & 0xf0) != 0x00 && (code & 0xf0) != 0x80
		&& (code & 0xf0) != 0x90;
}

static void reach(u8 * out, const u8 * keep_in, const int *tgt)
{
	int *wl = xcalloc(sizeof(int) * (ncb * 2 + 8)), nw = 0;
	u8 *keep = xcalloc(ncb + 2);
	memcpy(keep, keep_in, ncb);	/* out may alias keep_in */
	memset(out, 0, ncb + 2);
	wl[nw++] = nl(keep, 0);
	while (nw)
	{
		int i = wl[--nw];
		if (i >= ncb)
			die("internal: code falls off end");
		if (out[i])
			continue;
		out[i] = 1;
		int c = cb[i].code;
		if (c == 0x18)
		{
			out[i + 1] = 1;
			wl[nw++] = nl(keep, i + 2);
		}
		else if (c == 0x05)
			wl[nw++] = nl(keep, tgt[i]);
		else if (c == 0x95)
		{
		}
		else if (c == 0x85 || (c & 7) != 5)
			wl[nw++] = nl(keep, i + 1);
		else
		{
			wl[nw++] = nl(keep, tgt[i]);
			wl[nw++] = nl(keep, i + 1);
		}
	}
	free(wl);
	free(keep);
}

/* instructions some jump currently lands on (after resolving removed ones) -
   a peephole may only merge or delete an instruction that another path could
   arrive at if it keeps that path's behaviour */
static void mark_jt(u8 * jt, const u8 * keep, const int *tgt)
{
	memset(jt, 0, ncb + 2);
	for (int i = 0; i < ncb; i++)
		if (keep[i] && (cb[i].code & 7) == 5 && cb[i].code != 0x85 && cb[i].code != 0x95
			&& tgt[i] >= 0)
			jt[nl(keep, tgt[i])] = 1;
}

/* does the instruction read / fully overwrite r0? (for the "r0 is dead" walk
   of the mov-relay fusion) */
static void r0_effect(const Insn * c, int *rd, int *wr)
{
	int cl = c->code & 7, op = c->code & 0xf0;
	*rd = *wr = 0;
	if (cl == 7 || cl == 4)
	{
		int srcread = (c->code & 8) && op != 0x80 && op != 0xd0;
		*rd = (c->dst == 0 && op != 0xb0) || (srcread && c->src == 0);
		*wr = (c->dst == 0 && op == 0xb0);
	}
	else if (cl == 1)
	{
		*rd = (c->src == 0);
		*wr = (c->dst == 0);
	}
	else if (cl == 2)
		*rd = (c->dst == 0);
	else if (cl == 3)
		*rd = (c->dst == 0 || c->src == 0);
	else if (cl == 5)
	{
		if (c->code == 0x85)
			*wr = 1;
		else
			*rd = 1;
	}							/* CALL clobbers r0; any other jump/exit:
								   assume it may read */
	else
		*rd = 1;
}

static int inverse_jop(int code)
{								/* inverted condition of a conditional jump,
								   or -1 if this ISA level has none */
	int op = code & 0xf0, rest = code & 0x0f, n = -1;
	switch (op)
	{
	case 0x10:
		n = 0x50;
		break;
	case 0x50:
		n = 0x10;
		break;
	case 0x20:
		n = use_v2 ? 0xb0 : -1;
		break;
	case 0xb0:
		n = use_v2 ? 0x20 : -1;
		break;
	case 0x30:
		n = use_v2 ? 0xa0 : -1;
		break;
	case 0xa0:
		n = use_v2 ? 0x30 : -1;
		break;
	case 0x60:
		n = use_v2 ? 0xd0 : -1;
		break;
	case 0xd0:
		n = use_v2 ? 0x60 : -1;
		break;
	case 0x70:
		n = use_v2 ? 0xc0 : -1;
		break;
	case 0xc0:
		n = use_v2 ? 0x70 : -1;
		break;
	}
	return n < 0 ? -1 : n | rest;
}

static void finish_prog(Func * f)
{
	int *tgt = xcalloc(sizeof(int) * (ncb + 1));
	for (int i = 0; i < ncb; i++)
		tgt[i] = -1;
	for (int i = 0; i < nfix; i++)
	{
		if (lpos[fix[i].lab] < 0)
			die("internal: unplaced label");
		tgt[fix[i].idx] = lpos[fix[i].lab];
	}
	u8 *all = xcalloc(ncb + 2);
	memset(all, 1, ncb);
	u8 *live = xcalloc(ncb + 2), *jt = xcalloc(ncb + 2);
	reach(live, all, tgt);
	{							/* 1. jump threading: a jump to an
								   unconditional goto goes straight to that
								   goto's target; a goto to an exit becomes an 
								   exit */
		for (int i = 0; i < ncb; i++)
		{
			if (!live[i] || (cb[i].code & 7) != 5 || cb[i].code == 0x85 || cb[i].code == 0x95)
				continue;
			int t = nl(live, tgt[i]);
			for (int hop = 0; hop < 8 && t < ncb && cb[t].code == 0x05 && nl(live, tgt[t]) != t;
				 hop++)
				t = nl(live, tgt[t]);
			if (t < ncb && cb[i].code == 0x05 && cb[t].code == 0x95)
			{
				cb[i].code = 0x95;
				cb[i].dst = cb[i].src = 0;
				cb[i].off = 0;
				cb[i].imm = 0;
				tgt[i] = -1;
				continue;
			}
			tgt[i] = t;
		}
		reach(live, live, tgt);
	}
	{							/* 2. a goto that only skips removed code to
								   the next instruction, and 3. "if c goto +1; 
								   goto L" -> "if !c goto L" (to a fixpoint) */
		for (int again = 1; again;)
		{
			again = 0;
			for (int i = 0; i < ncb; i++)
			{
				if (!live[i])
					continue;
				if (cb[i].code == 0x05 && nl(live, tgt[i]) == nl(live, i + 1))
				{
					live[i] = 0;
					again = 1;
					continue;
				}
			}
			mark_jt(jt, live, tgt);
			for (int i = 0; i < ncb; i++)
			{
				if (!live[i] || !is_cond_jmp(cb[i].code))
					continue;
				int j = nl(live, i + 1);
				if (j >= ncb || cb[j].code != 0x05 || jt[j])
					continue;
				if (nl(live, tgt[i]) != nl(live, j + 1))
					continue;
				int inv = inverse_jop(cb[i].code);
				if (inv < 0)
					continue;
				cb[i].code = (uint8_t) inv;
				tgt[i] = tgt[j];
				live[j] = 0;
				again = 1;
				mark_jt(jt, live, tgt);
			}
		}
		reach(live, live, tgt);
	}
	{
		mark_jt(jt, live, tgt);
		/* 4. redundant sign-extend directly followed by a zero-extend of the
		   same register: the zero-extend alone is the same */
		for (int i = 0; i + 2 < ncb; i++)
		{
			if (!live[i] || !live[i + 1] || !live[i + 2])
				continue;
			Insn *a = &cb[i], *b = &cb[i + 1], *c = &cb[i + 2];
			if (a->code == 0x67 && a->imm == 32 && b->code == 0xc7 && b->imm == 32
				&& a->dst == b->dst && c->code == 0xbc && c->dst == a->dst && c->src == a->dst
				&& !jt[i + 1] && !jt[i + 2])
				live[i] = live[i + 1] = 0;
		}
		/* 5. "w = w" right after an instruction that already leaves the upper 
		   32 bits zero (32-bit load or 32-bit ALU result) */
		for (int i = 0, prev = -1; i < ncb; i++)
		{
			if (!live[i])
				continue;
			Insn *c = &cb[i];
			if (prev >= 0 && c->code == 0xbc && c->dst == c->src && !jt[i])
			{
				Insn *p = &cb[prev];
				if ((p->code == 0x61 && p->dst == c->dst)
					|| ((p->code & 7) == 4 && p->dst == c->dst && (p->code & 0xf0) != 0xd0))
				{
					live[i] = 0;
					continue;
				}
			}
			prev = i;
			if (c->code == 0x18)
				i++;
		}
		/* 6. store followed by a reload of the same 8-byte slot: reuse the
		   register that was just stored */
		for (int i = 0, prev = -1; i < ncb; i++)
		{
			if (!live[i])
				continue;
			Insn *c = &cb[i];
			if (prev >= 0 && c->code == 0x79 && !jt[i])
			{
				Insn *p = &cb[prev];
				if (p->code == 0x7b && p->dst == c->src && p->off == c->off)
				{
					if (c->dst == p->src)
					{
						live[i] = 0;
						continue;
					}
					c->code = 0xbf;
					c->src = p->src;
					c->off = 0;
				}
			}
			prev = i;
			if (c->code == 0x18)
				i++;
		}
		/* 7. "r0 = rX; rY = r0" -> "rY = rX": the hop through r0 is only a
		   relay for a value that was never wanted in r0. Safe only if r0 is
		   dead afterwards, which is checked on the real code: walk the
		   straight-line instructions after the pair; r0 must be overwritten
		   before anything reads it (any jump/exit or the end of a
		   16-instruction window blocks the fusion). The second instruction
		   must not be a jump target; the first may be - jumps to it land on
		   the fused move. */
		for (int i = 0; i + 1 < ncb; i++)
		{
			if (!live[i])
				continue;
			int i1 = nl(live, i + 1);
			if (i1 >= ncb || jt[i1])
				continue;
			Insn *a = &cb[i], *b = &cb[i1];
			if (!
				(a->code == 0xbf && a->dst == 0 && a->src != 0 && b->code == 0xbf && b->src == 0
				 && b->dst != 0))
				continue;
			int safe = 0, steps = 0;
			for (int j = nl(live, i1 + 1); j < ncb && steps < 16; j = nl(live, j + 1))
			{
				steps++;
				Insn *c = &cb[j];
				int rd, wr;
				if (c->code == 0x18)
				{
					if (c->dst == 0)
					{
						safe = 1;
						break;
					}
					j++;
					continue;
				}				/* ld_imm64 spans two slots */
				r0_effect(c, &rd, &wr);
				if (rd)
					break;
				if (wr)
				{
					safe = 1;
					break;
				}
			}
			if (!safe)
				continue;
			if (a->src == b->dst)
				live[i] = live[i1] = 0;
			else
			{
				b->src = a->src;
				live[i] = 0;
			}
		}
		reach(live, live, tgt);
	}
	int *ni = xcalloc(sizeof(int) * (ncb + 2)), k = 0;
	for (int i = 0; i < ncb; i++)
	{
		ni[i] = k;
		if (live[i])
			k++;
	}
	ni[ncb] = k;
	Prog p;
	memset(&p, 0, sizeof p);
	p.f = f;
	p.c = xcalloc(sizeof(Insn) * (k + 1));
	p.n = k;
	for (int i = 0; i < ncb; i++)
		if (live[i])
		{
			Insn x = cb[i];
			if (tgt[i] >= 0)
			{
				int off = ni[tgt[i]] - (ni[i] + 1);
				if (off > 32767 || off < -32768)
					die("jump too far in '%s'", f->name);
				x.off = (int16_t) off;
			}
			p.c[ni[i]] = x;
		}
	p.ridx = xcalloc(sizeof(int) * (nrels + 1));
	p.rvar = xcalloc(sizeof(Var *) * (nrels + 1));
	for (int i = 0; i < nrels; i++)
		if (live[rels[i].idx])
		{
			p.ridx[p.nrel] = ni[rels[i].idx];
			p.rvar[p.nrel++] = rels[i].v;
		}
	PUSH(progs, p);
}

static void gen_entry(Func * f)
{
	ncb = nrels = nlab = nfix = nglab = lab_base = 0;
	stk_cur = stk_max = 0;
	regmask = 0;
	inl = 0;
	ret_lab = brk_lab = cont_lab = -1;
	cur_file = f->name;
	compute_hot_vars(f);
	cur_nfree = count_free_regs();
	if (f->np > 1)
		die("program '%s': entry functions take one argument (ctx)", f->name);
	static Var *entry_owned[1];
	n_pending_owned = 0;
	if (f->np == 1)
	{
		Var *v = f->params[0];
		v->addr = v->addr;
		gen_decl(v);
		if (v->reg >= 0)
		{
			mov_r(v->reg, 1);
			entry_owned[0] = v;
			n_pending_owned = 1;
		}
		else
			stx(v->ty->size, 10, v->off, 1);
	}
	pending_owned = entry_owned;
	gen_stmt(f->body);
	mov_i(0, 0);
	emit(0x95, 0, 0, 0, 0);
	for (int i = 0; i < nglab; i++)
		if (!glab[i].def)
			die("label '%s' used but not defined", glab[i].n);
	finish_prog(f);
}

/* ======================= ELF output / disassembler ======================= */
typedef struct
{
	u8 *p;
	size_t n, cap;
} Buf;
static void bput(Buf * b, const void *d, size_t n)
{
	if (b->n + n > b->cap)
	{
		b->cap = (b->n + n) * 2 + 64;
		b->p = realloc(b->p, b->cap);
	}
	if (n)
		memcpy(b->p + b->n, d, n);
	b->n += n;
}

static void bw(Buf * b, u64 v, int n)
{
	u8 t[8];
	for (int i = 0; i < n; i++)
		t[i] = (u8) (v >> (8 * i));
	bput(b, t, n);
}

static void bpad(Buf * b, int al)
{
	while (b->n % al)
		bw(b, 0, 1);
}

static int stradd(Buf * b, const char *s)
{
	int o = (int)b->n;
	bput(b, s, strlen(s) + 1);
	return o;
}

static int bstr(Buf * b, const char *s)
{
	return stradd(b, s);
}

typedef struct
{
	char *name;
	Buf d;
} DSec;
typedef struct
{
	int name, type;
	u64 flags, off, size;
	int link, info;
	u64 align, entsize;
} SH;

static void write_elf(const char *path)
{
	DSec ds[24];
	int nds = 0;
	memset(ds, 0, sizeof ds);
	for (int i = 0; i < globals.n; i++)
	{
		Var *g = globals.p[i];
		const char *sn = g->sec ? g->sec : ".data";
		int j;
		for (j = 0; j < nds; j++)
			if (!strcmp(ds[j].name, sn))
				break;
		if (j == nds)
		{
			if (nds >= 24)
				die("too many sections");
			ds[nds].name = (char *)sn;
			nds++;
		}
		bpad(&ds[j].d, g->ty->align > 8 ? 8 : (g->ty->align ? g->ty->align : 1));
		g->off = (int)ds[j].d.n;
		g->sym = j;
		bput(&ds[j].d, g->data, g->ty->size);
	}
	{							/* minimal BTF describing BTF-defined maps
								   (libbpf >= 1.0 requires it); only when such 
								   maps exist */
		int nm = 0;
		for (int i = 0; i < globals.n; i++)
		{
			if (globals.p[i]->mdty)
				nm++;
			if (!legacy_maps && globals.p[i]->sec && !strcmp(globals.p[i]->sec, "maps"))
				fprintf(stderr,
						"warning: legacy 'maps' section is rejected by libbpf >= 1.0; use __uint/__type map syntax\n");
		}
		if (nm)
		{
			Buf ty = { 0 }
			, bs =
			{
			0};
			int n = 0;
			bw(&bs, 0, 1);
#define BSTR(x) bstr(&bs, x)
#define BINT(nmz, sz, sg) (bw(&ty, BSTR(nmz), 4), bw(&ty, 1u << 24, 4), bw(&ty, sz, 4), bw(&ty, ((sg) ? 1u << 24 : 0) | ((sz) * 8), 4), ++n)
			int t_int = BINT("int", 4, 1), t_idx = BINT("__ARRAY_SIZE_TYPE__", 4, 0), t_u8 =
				BINT("unsigned char", 1, 0);
			int t_u16 = BINT("unsigned short", 2, 0), t_u32 = BINT("unsigned int", 4, 0), t_u64 =
				BINT("unsigned long long", 8, 0);
			(void)t_u32;
			(void)t_u64;
			(void)t_u16;
			int bi[9] = { 0, t_u8, t_u16, 0, t_u32, 0, 0, 0, t_u64 };
			int varid[64], nv = 0;
			for (int i = 0; i < globals.n && nv < 64; i++)
			{
				Var *g = globals.p[i];
				if (!g->mdty)
					continue;
				Type *m = g->mdty;
				int mt[16];
				for (int k = 0; k < m->mdn; k++)
				{
					int elem;
					if (m->mdisu[k])
					{
						bw(&ty, 0, 4);
						bw(&ty, 3u << 24, 4);
						bw(&ty, 0, 4);
						bw(&ty, t_int, 4);
						bw(&ty, t_idx, 4);
						bw(&ty, (u64) m->mdval[k], 4);
						elem = ++n;
					}
					else
					{
						int sz = (int)m->mdval[k];
						if (sz == 1 || sz == 2 || sz == 4 || sz == 8)
							elem = bi[sz];
						else
						{
							bw(&ty, 0, 4);
							bw(&ty, 3u << 24, 4);
							bw(&ty, 0, 4);
							bw(&ty, t_u8, 4);
							bw(&ty, t_idx, 4);
							bw(&ty, (u64) sz, 4);
							elem = ++n;
						}
					}
					bw(&ty, 0, 4);
					bw(&ty, 2u << 24, 4);
					bw(&ty, elem, 4);
					mt[k] = ++n;
				}
				int nmo[16];
				for (int k = 0; k < m->mdn; k++)
					nmo[k] = BSTR(m->mdname[k]);
				bw(&ty, 0, 4);
				bw(&ty, (4u << 24) | m->mdn, 4);
				bw(&ty, 8 * m->mdn, 4);
				for (int k = 0; k < m->mdn; k++)
				{
					bw(&ty, nmo[k], 4);
					bw(&ty, mt[k], 4);
					bw(&ty, 64 * k, 4);
				}
				int sid = ++n;
				bw(&ty, BSTR(g->name), 4);
				bw(&ty, 14u << 24, 4);
				bw(&ty, sid, 4);
				bw(&ty, 1, 4);
				varid[nv++] = ++n;
			}
			int mj = -1;
			for (int j = 0; j < nds; j++)
				if (!strcmp(ds[j].name, ".maps"))
					mj = j;
			bw(&ty, BSTR(".maps"), 4);
			bw(&ty, (15u << 24) | nv, 4);
			bw(&ty, mj >= 0 ? ds[mj].d.n : 0, 4);
			for (int i = 0, k = 0; i < globals.n && k < nv; i++)
				if (globals.p[i]->mdty)
				{
					bw(&ty, varid[k++], 4);
					bw(&ty, globals.p[i]->off, 4);
					bw(&ty, globals.p[i]->ty->size, 4);
				}
			if (nds >= 24)
				die("too many sections");
			ds[nds].name = ".BTF";
			bw(&ds[nds].d, 0xeB9F, 2);
			bw(&ds[nds].d, 1, 1);
			bw(&ds[nds].d, 0, 1);
			bw(&ds[nds].d, 24, 4);
			bw(&ds[nds].d, 0, 4);
			bw(&ds[nds].d, ty.n, 4);
			bw(&ds[nds].d, ty.n, 4);
			bw(&ds[nds].d, bs.n, 4);
			bput(&ds[nds].d, ty.p, ty.n);
			bput(&ds[nds].d, bs.p, bs.n);
			nds++;
		}
	}
	int have_lic = 0;
	for (int j = 0; j < nds; j++)
		if (!strcmp(ds[j].name, "license"))
			have_lic = 1;
	if (!have_lic)
	{
		ds[nds].name = "license";
		bput(&ds[nds].d, "GPL", 4);
		nds++;
	}
	int np = progs.n, nrs = 0;
	for (int i = 0; i < np; i++)
		if (progs.p[i].nrel)
			nrs++;
	int first_rel = 1 + np, first_data = first_rel + nrs, symtab = first_data + nds, strtab =
		symtab + 1, shstr = symtab + 2, nsec = shstr + 1;
	Buf st = { 0 }, ss =
	{
	0}, sh =
	{
	0};
	bw(&st, 0, 8);
	bw(&st, 0, 8);
	bw(&st, 0, 8);
	bw(&ss, 0, 1);
	bw(&sh, 0, 1);
	for (int i = 0; i < np; i++)
	{
		Prog *p = &progs.p[i];
		bw(&st, stradd(&ss, p->f->name), 4);
		bw(&st, (1 << 4) | 2, 1);
		bw(&st, 0, 1);
		bw(&st, 1 + i, 2);
		bw(&st, 0, 8);
		bw(&st, (u64) p->n * 8, 8);
	}
	for (int i = 0; i < globals.n; i++)
	{
		Var *g = globals.p[i];
		bw(&st, stradd(&ss, g->name), 4);
		bw(&st, (1 << 4) | 1, 1);
		bw(&st, 0, 1);
		bw(&st, first_data + g->sym, 2);
		bw(&st, g->off, 8);
		bw(&st, g->ty->size, 8);
		g->sym = 1 + np + i;	/* symbol index (section index no longer
								   needed) */
	}
	SH *shs = xcalloc(sizeof(SH) * nsec);
	Buf out = { 0 };
	for (int z_ = 0; z_ < 8; z_++)
		bw(&out, 0, 8);
	int ri = first_rel;
	for (int i = 0; i < np; i++)
	{
		Prog *p = &progs.p[i];
		bpad(&out, 8);
		SH *s = &shs[1 + i];
		s->name = stradd(&sh, p->f->sec ? p->f->sec : ".text");
		s->type = 1;
		s->flags = 6;
		s->off = out.n;
		s->size = (u64) p->n * 8;
		s->align = 8;
		for (int k = 0; k < p->n; k++)
		{
			Insn *x = &p->c[k];
			bw(&out, x->code, 1);
			bw(&out, (x->dst & 15) | (x->src << 4), 1);
			bw(&out, (uint16_t) x->off, 2);
			bw(&out, (uint32_t) x->imm, 4);
		}
		if (p->nrel)
		{
			bpad(&out, 8);
			SH *r = &shs[ri];
			char nm[256];
			snprintf(nm, sizeof nm, ".rel%s", p->f->sec ? p->f->sec : ".text");
			r->name = stradd(&sh, nm);
			r->type = 9;
			r->off = out.n;
			r->size = (u64) p->nrel * 16;
			r->link = symtab;
			r->info = 1 + i;
			r->align = 8;
			r->entsize = 16;
			for (int k = 0; k < p->nrel; k++)
			{
				bw(&out, (u64) p->ridx[k] * 8, 8);
				bw(&out, ((u64) p->rvar[k]->sym << 32) | 1, 8);
			}
			ri++;
		}
	}
	for (int j = 0; j < nds; j++)
	{
		bpad(&out, 8);
		SH *s = &shs[first_data + j];
		s->name = stradd(&sh, ds[j].name);
		s->type = 1;
		s->flags = strcmp(ds[j].name, ".BTF") ? 3 : 0;
		s->off = out.n;
		s->size = ds[j].d.n;
		s->align = 4;
		bput(&out, ds[j].d.p, ds[j].d.n);
	}
	bpad(&out, 8);
	{
		SH *s = &shs[symtab];
		s->name = stradd(&sh, ".symtab");
		s->type = 2;
		s->off = out.n;
		s->size = st.n;
		s->link = strtab;
		s->info = 1;
		s->align = 8;
		s->entsize = 24;
		bput(&out, st.p, st.n);
	}
	{
		SH *s = &shs[strtab];
		s->name = stradd(&sh, ".strtab");
		s->type = 3;
		s->off = out.n;
		s->size = ss.n;
		s->align = 1;
		bput(&out, ss.p, ss.n);
	}
	{
		SH *s = &shs[shstr];
		s->name = stradd(&sh, ".shstrtab");
		s->type = 3;
		s->align = 1;
		s->off = out.n;
		s->size = sh.n;
		bput(&out, sh.p, sh.n);
	}
	bpad(&out, 8);
	u64 shoff = out.n;
	for (int i = 0; i < nsec; i++)
	{
		SH *s = &shs[i];
		bw(&out, s->name, 4);
		bw(&out, s->type, 4);
		bw(&out, s->flags, 8);
		bw(&out, 0, 8);
		bw(&out, s->off, 8);
		bw(&out, s->size, 8);
		bw(&out, s->link, 4);
		bw(&out, s->info, 4);
		bw(&out, s->align, 8);
		bw(&out, s->entsize, 8);
	}
	Buf h = { 0 };
	bput(&h, "\x7f" "ELF\2\1\1\0\0\0\0\0\0\0\0\0", 16);
	bw(&h, 1, 2);
	bw(&h, 247, 2);
	bw(&h, 1, 4);
	bw(&h, 0, 8);
	bw(&h, 0, 8);
	bw(&h, shoff, 8);
	bw(&h, 0, 4);
	bw(&h, 64, 2);
	bw(&h, 0, 2);
	bw(&h, 0, 2);
	bw(&h, 64, 2);
	bw(&h, nsec, 2);
	bw(&h, shstr, 2);
	memcpy(out.p, h.p, 64);
	FILE *f = fopen(path, "wb");
	if (!f)
	{
		perror(path);
		exit(1);
	}
	fwrite(out.p, 1, out.n, f);
	fclose(f);
}

static void dis(Prog * p)
{
	static const char *aop[] =
		{ "+=", "-=", "*=", "/=", "|=", "&=", "<<=", ">>=", "neg", "%=", "^=", "=", "s>>=", "end",
		"?", "?"
	};
	static const char *jop[] =
		{ "goto", "==", ">", ">=", "&", "!=", "s>", "s>=", "call", "exit", "<", "<=", "s<", "s<=",
		"?", "?"
	};
	printf("%s:    ; section %s, %d insns\n", p->f->name, p->f->sec ? p->f->sec : ".text", p->n);
	for (int i = 0; i < p->n; i++)
	{
		Insn *x = &p->c[i];
		int cl = x->code & 7, op = x->code >> 4, sz = x->code & 0x18;
		const char *w = sz == 0x18 ? "u64" : sz == 0x00 ? "u32" : sz == 0x08 ? "u16" : "u8";
		printf("%4d: ", i);
		if (x->code == 0x18)
		{
			printf("r%d = 0x%llx ll\n", x->dst,
				   ((u64) (uint32_t) p->c[i + 1].imm << 32) | (uint32_t) x->imm);
			i++;
		}
		else if (cl == 7 || cl == 4)
		{
			const char *r = cl == 7 ? "r" : "w";
			if (op == 8)
				printf("%s%d = -%s%d\n", r, x->dst, r, x->dst);
			else if (op == 13)
				printf("%s%d = be%d(%s%d)\n", r, x->dst, x->imm, r, x->dst);
			else if (x->code & 8)
				printf("%s%d %s %s%d\n", r, x->dst, aop[op], r, x->src);
			else
				printf("%s%d %s %d\n", r, x->dst, aop[op], x->imm);
		}
		else if (cl == 1)
			printf("r%d = *(%s *)(r%d %+d)\n", x->dst, w, x->src, x->off);
		else if (cl == 3 && (x->code & 0xe0) == 0xc0)
			printf("lock *(%s *)(r%d %+d) += r%d\n", w, x->dst, x->off, x->src);
		else if (cl == 3)
			printf("*(%s *)(r%d %+d) = r%d\n", w, x->dst, x->off, x->src);
		else if (cl == 2)
			printf("*(%s *)(r%d %+d) = %d\n", w, x->dst, x->off, x->imm);
		else if (cl == 5)
		{
			if (op == 9)
				printf("exit\n");
			else if (op == 8)
				printf("call %d\n", x->imm);
			else if (op == 0)
				printf("goto %+d <%d>\n", x->off, i + 1 + x->off);
			else if (x->code & 8)
				printf("if r%d %s r%d goto %+d <%d>\n", x->dst, jop[op], x->src, x->off,
					   i + 1 + x->off);
			else
				printf("if r%d %s %d goto %+d <%d>\n", x->dst, jop[op], x->imm, x->off,
					   i + 1 + x->off);
		}
		else
			printf(".insn %02x\n", x->code);
	}
}


/* ======================= optional: kernel verifier test (-V)
   ======================= */
#ifdef __linux__
#ifndef __NR_bpf
# if defined(__arm__)
#  define __NR_bpf 386
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__i386__)
#  define __NR_bpf 357
# endif
#endif
union vattr
{
	struct
	{
		uint32_t type, key_size, value_size, max_entries, flags;
	} m;
	struct
	{
		uint32_t type, insn_cnt;
		u64 insns, license;
		uint32_t log_level, log_size;
		u64 log_buf;
		uint32_t kern_version, flags;
		char name[16];
		uint32_t ifindex, expected_attach_type;
	} p;
	char raw[128];
};
static long vsys(int cmd, union vattr *a)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, a, sizeof *a);
#else
	(void)cmd;
	(void)a;
	errno = ENOSYS;
	return -1;
#endif
}

#define VPTR(x) ((u64)(uintptr_t)(x))
static int vprog_type(const char *sec)
{
	static const struct
	{
		const char *p;
		int t;
	} T_[] =
	{
		{
		"socket", 1},
		{
		"kprobe/", 2},
		{
		"kretprobe/", 2},
		{
		"classifier", 3},
		{
		"tc", 3},
		{
		"action", 4},
		{
		"tracepoint/", 5},
		{
		"tp/", 5},
		{
		"xdp", 6},
		{
		"perf_event", 7},
		{
		"cgroup/skb", 8},
		{
		"cgroup_skb/", 8},
		{
		"cgroup/sock", 9},
		{
		"lwt_in", 10},
		{
		"lwt_out", 11},
		{
		"lwt_xmit", 12},
		{
		"sockops", 13},
		{
		"sk_skb", 14},
		{
		"cgroup/dev", 15},
		{
		"sk_msg", 16},
		{
		"raw_tracepoint/", 17},
		{
		"raw_tp/", 17},
		{
		"cgroup/bind", 18},
		{
		"cgroup/connect", 18},
		{
		"cgroup/sendmsg", 18},
		{
		"cgroup/recvmsg", 18},
		{
		"cgroup/getpeername", 18},
		{
		"cgroup/getsockname", 18},
		{
		"cgroup/post_bind", 9},
		{
	0, 0}};
	for (int i = 0; T_[i].p; i++)
		if (!strncmp(sec, T_[i].p, strlen(T_[i].p)))
			return T_[i].t;
	return -1;
}

/* expected_attach_type: required by the kernel for sock_addr / post_bind /
   sock_create programs */
static int vattach_type(const char *sec)
{
	static const struct
	{
		const char *p;
		int t;
	} A_[] =
	{
		{
		"cgroup/bind4", 8},
		{
		"cgroup/bind6", 9},
		{
		"cgroup/connect4", 10},
		{
		"cgroup/connect6", 11},
		{
		"cgroup/post_bind4", 12},
		{
		"cgroup/post_bind6", 13},
		{
		"cgroup/sendmsg4", 14},
		{
		"cgroup/sendmsg6", 15},
		{
		"cgroup/recvmsg4", 19},
		{
		"cgroup/recvmsg6", 20},
		{
		"cgroup/getpeername4", 29},
		{
		"cgroup/getpeername6", 30},
		{
		"cgroup/getsockname4", 31},
		{
		"cgroup/getsockname6", 32},
		{
		"cgroup/sock_create", 2},
		{
		"cgroup/sock_release", 34},
		{
		"cgroup_skb/egress", 1},
		{
	0, 0}};
	for (int i = 0; A_[i].p; i++)
		if (!strncmp(sec, A_[i].p, strlen(A_[i].p)))
			return A_[i].t;
	return 0;
}

static int vmap_def(Var * g, uint32_t d[5])
{
	memset(d, 0, 5 * sizeof *d);
	if (g->mdty)
	{
		for (int k = 0; k < g->mdty->mdn; k++)
		{
			const char *a = g->mdty->mdname[k];
			uint32_t v = (uint32_t) g->mdty->mdval[k];
			if (!strcmp(a, "type"))
				d[0] = v;
			else if (!strcmp(a, "key") || !strcmp(a, "key_size"))
				d[1] = v;
			else if (!strcmp(a, "value") || !strcmp(a, "value_size"))
				d[2] = v;
			else if (!strcmp(a, "max_entries"))
				d[3] = v;
			else if (!strcmp(a, "map_flags"))
				d[4] = v;
		}
		return 1;
	}
	if (g->sec && !strcmp(g->sec, "maps") && g->ty->size >= 20)
	{
		for (int k = 0; k < 5; k++)
			d[k] =
				g->data[k * 4] | g->data[k * 4 + 1] << 8 | g->data[k * 4 +
																   2] << 16 | (uint32_t) g->data[k
																								 *
																								 4
																								 +
																								 3]
				<< 24;
		return 1;
	}
	return 0;
}

static int verify_all(int force_type)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rl);	/* kernels < 5.11 charge map memory to it */
	const char *lic = "GPL";
	uint32_t kver = 0;
	struct utsname un;
	if (!uname(&un))
	{
		int a = 0, b = 0, c = 0;
		if (sscanf(un.release, "%d.%d.%d", &a, &b, &c) >= 2)
			kver = (a << 16) + (b << 8) + (c > 255 ? 255 : c);
	}
	for (int i = 0; i < globals.n; i++)
	{
		Var *g = globals.p[i];
		if (g->sec && !strcmp(g->sec, "license"))
			lic = (const char *)g->data;
		if (g->sec && !strcmp(g->sec, "version") && g->ty->size >= 4)
			kver = g->data[0] | g->data[1] << 8 | g->data[2] << 16 | (uint32_t) g->data[3] << 24;
	}
	int *mfd = xcalloc(sizeof(int) * (globals.n + 1));
	for (int i = 0; i <= globals.n; i++)
		mfd[i] = -1;
	char *log = xcalloc(1 << 20);
	int bad = 0;
	for (int pi = 0; pi < progs.n; pi++)
	{
		Prog *p = &progs.p[pi];
		const char *sec = p->f->sec ? p->f->sec : ".text";
		int ok = 1;
		int type = force_type > 0 ? force_type : vprog_type(sec);
		if (type < 0)
		{
			fprintf(stderr, "verify: %s: cannot guess program type from section '%s' (use -T N)\n",
					p->f->name, sec);
			bad++;
			continue;
		}
		u8 *code = xcalloc((size_t) p->n * 8 + 8);
		for (int k = 0; k < p->n; k++)
		{
			Insn *x = &p->c[k];
			u8 *o = code + k * 8;
			o[0] = x->code;
			o[1] = (u8) ((x->dst & 15) | (x->src << 4));
			o[2] = (u8) (x->off & 0xff);
			o[3] = (u8) ((x->off >> 8) & 0xff);
			uint32_t im = (uint32_t) x->imm;
			for (int j = 0; j < 4; j++)
				o[4 + j] = (u8) (im >> (8 * j));
		}
		for (int r = 0; r < p->nrel && ok; r++)
		{
			Var *g = p->rvar[r];
			int gi = 0;
			while (gi < globals.n && globals.p[gi] != g)
				gi++;
			uint32_t d[5];
			if (!vmap_def(g, d))
			{
				fprintf(stderr, "verify: %s: relocation against '%s' which is not a map\n",
						p->f->name, g->name);
				ok = 0;
				break;
			}
			if (mfd[gi] < 0)
			{
				union vattr a;
				memset(&a, 0, sizeof a);
				a.m.type = d[0];
				a.m.key_size = d[1];
				a.m.value_size = d[2];
				a.m.max_entries = d[3];
				a.m.flags = d[4];
				mfd[gi] = (int)vsys(0, &a);
				if (mfd[gi] < 0)
				{
					fprintf(stderr,
							"verify: cannot create map '%s' (type %u key %u value %u max %u): %s\n",
							g->name, d[0], d[1], d[2], d[3], strerror(errno));
					if (errno == EPERM)
						fprintf(stderr,
								"        bpf() needs root (uid=%d), SELinux permission and a high enough RLIMIT_MEMLOCK\n",
								(int)geteuid());
					ok = 0;
					break;
				}
			}
			size_t off = (size_t) p->ridx[r] * 8;
			code[off + 1] = (u8) ((code[off + 1] & 0x0f) | (1 << 4));
			int32_t fd = mfd[gi];
			memcpy(code + off + 4, &fd, 4);
		}
		if (!ok)
		{
			bad++;
			continue;
		}
		union vattr a;
		memset(&a, 0, sizeof a);
		a.p.type = type;
		a.p.insn_cnt = p->n;
		a.p.insns = VPTR(code);
		a.p.license = VPTR(lic);
		a.p.log_level = 1;
		a.p.log_size = 1 << 20;
		a.p.log_buf = VPTR(log);
		a.p.kern_version = kver;
		log[0] = 0;
		a.p.expected_attach_type = (uint32_t) vattach_type(sec);
		int fd = (int)vsys(5, &a);
		int e = errno;
		if (fd >= 0)
		{
			char *last = log + strlen(log);
			while (last > log && (last[-1] == '\n' || last[-1] == ' '))
				*--last = 0;
			while (last > log && last[-1] != '\n')
				last--;
			printf("verify: %s [%s] type %d: OK, %d insns%s%s\n", p->f->name, sec, type, p->n,
				   *last ? "; kernel: " : "", last);
			close(fd);
		}
		else
		{
			fprintf(stderr, "verify: %s [%s] type %d: REJECTED: %s\n", p->f->name, sec, type,
					strerror(e));
			if (log[0])
				fprintf(stderr, "---- verifier log ----\n%s\n----------------------\n", log);
			else if (e == EPERM)
				fprintf(stderr, "        bpf() needs root (uid=%d) / SELinux permission\n",
						(int)geteuid());
			bad++;
		}
	}
	for (int i = 0; i < globals.n; i++)
		if (mfd[i] >= 0)
			close(mfd[i]);
	return bad;
}
#endif

/* ======================= prelude / main ======================= */
#define P(s) s "\n"
static const char PRELUDE[] =
P("#define NULL ((void*)0)") P("#define true 1") P("#define false 0") P("#define __BPF__ 1")
P("#define likely(x) (x)") P("#define unlikely(x) (x)")
P("#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))") P("#define htons bpf_htons")
P("#define ntohs bpf_ntohs") P("#define htonl bpf_htonl") P("#define ntohl bpf_ntohl")
P("typedef unsigned char u8,__u8,uint8_t; typedef signed char s8,__s8,int8_t;")
P("typedef unsigned short u16,__u16,__be16,__le16,uint16_t; typedef short s16,__s16,int16_t;")
P("typedef unsigned int u32,__u32,__be32,__le32,__wsum,uint32_t; typedef int s32,__s32,int32_t;")
P("typedef unsigned long long u64,__u64,uint64_t; typedef long long s64,__s64,int64_t;")
P("typedef unsigned char bool; typedef unsigned long size_t;")
P("enum { BPF_MAP_TYPE_UNSPEC, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,")
P("  BPF_MAP_TYPE_PERCPU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_STACK_TRACE, BPF_MAP_TYPE_CGROUP_ARRAY, BPF_MAP_TYPE_LRU_HASH,")
P("  BPF_MAP_TYPE_LRU_PERCPU_HASH, BPF_MAP_TYPE_LPM_TRIE, BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS, BPF_MAP_TYPE_DEVMAP,")
P("  BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP, BPF_MAP_TYPE_SOCKHASH, BPF_MAP_TYPE_CGROUP_STORAGE,")
P("  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK, BPF_MAP_TYPE_SK_STORAGE,")
P("  BPF_MAP_TYPE_DEVMAP_HASH, BPF_MAP_TYPE_STRUCT_OPS, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_INODE_STORAGE };") P("enum { BPF_RB_NO_WAKEUP = 1, BPF_RB_FORCE_WAKEUP = 2 };") P("enum { BPF_ANY, BPF_NOEXIST, BPF_EXIST };")
P("enum { BPF_F_NO_PREALLOC = 1, BPF_F_INGRESS = 1, BPF_F_RECOMPUTE_CSUM = 1, BPF_F_CURRENT_CPU = 0xffffffff, TASK_COMM_LEN = 16 };") P("enum { XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT };")
P("enum { TC_ACT_UNSPEC = -1, TC_ACT_OK = 0, TC_ACT_RECLASSIFY, TC_ACT_SHOT, TC_ACT_PIPE, TC_ACT_STOLEN, TC_ACT_QUEUED, TC_ACT_REPEAT, TC_ACT_REDIRECT };") P("enum { SK_DROP, SK_PASS };")
P("enum { ETH_P_IP = 0x0800, ETH_P_ARP = 0x0806, ETH_P_8021Q = 0x8100, ETH_P_IPV6 = 0x86DD };") P("enum { IPPROTO_ICMP = 1, IPPROTO_TCP = 6, IPPROTO_UDP = 17, IPPROTO_IPV6 = 41, IPPROTO_ICMPV6 = 58, AF_INET = 2, AF_INET6 = 10 };")
P("struct bpf_map_def { unsigned int type, key_size, value_size, max_entries, map_flags; };") P("struct __sk_buff { u32 len, pkt_type, mark, queue_mapping, protocol, vlan_present, vlan_tci, vlan_proto, priority,")
P("  ingress_ifindex, ifindex, tc_index, cb[5], hash, tc_classid, data, data_end, napi_id, family, remote_ip4, local_ip4,") P("  remote_ip6[4], local_ip6[4], remote_port, local_port, data_meta; };") P("struct xdp_md { u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index; };") P("struct ethhdr { u8 h_dest[6]; u8 h_source[6]; u16 h_proto; };")
P("struct iphdr { u8 ver_ihl; u8 tos; u16 tot_len; u16 id; u16 frag_off; u8 ttl; u8 protocol; u16 check; u32 saddr; u32 daddr; };") P("struct ipv6hdr { u8 vtc; u8 flow[3]; u16 payload_len; u8 nexthdr; u8 hop_limit; u8 saddr[16]; u8 daddr[16]; };") P("struct udphdr { u16 source; u16 dest; u16 len; u16 check; };") P("struct tcphdr { u16 source; u16 dest; u32 seq; u32 ack_seq; u8 doff_res; u8 flags; u16 window; u16 check; u16 urg_ptr; };") P("#if defined(ARM32)") P("struct pt_regs { u32 uregs[18]; };") P("#define PT_REGS_PARM1(x) ((x)->uregs[0])") P("#define PT_REGS_PARM2(x) ((x)->uregs[1])")
P("#define PT_REGS_PARM3(x) ((x)->uregs[2])") P("#define PT_REGS_PARM4(x) ((x)->uregs[3])") P("#define PT_REGS_RC(x) ((x)->uregs[0])") P("#define PT_REGS_SP(x) ((x)->uregs[13])") P("#define PT_REGS_IP(x) ((x)->uregs[15])") P("#elif defined(X86_64)") P("struct pt_regs { u64 r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss; };") P("#define PT_REGS_PARM1(x) ((x)->di)") P("#define PT_REGS_PARM2(x) ((x)->si)") P("#define PT_REGS_PARM3(x) ((x)->dx)") P("#define PT_REGS_PARM4(x) ((x)->cx)") P("#define PT_REGS_PARM5(x) ((x)->r8)") P("#define PT_REGS_RC(x) ((x)->ax)") P("#define PT_REGS_SP(x) ((x)->sp)") P("#define PT_REGS_IP(x) ((x)->ip)") P("#else") P("struct pt_regs { u64 regs[31]; u64 sp; u64 pc; u64 pstate; };") P("#define PT_REGS_PARM1(x) ((x)->regs[0])") P("#define PT_REGS_PARM2(x) ((x)->regs[1])") P("#define PT_REGS_PARM3(x) ((x)->regs[2])") P("#define PT_REGS_PARM4(x) ((x)->regs[3])")
P("#define PT_REGS_PARM5(x) ((x)->regs[4])") P("#define PT_REGS_RC(x) ((x)->regs[0])") P("#define PT_REGS_SP(x) ((x)->sp)") P("#define PT_REGS_IP(x) ((x)->pc)") P("#endif");

	 static void def_macro(const char *spec)
{
	char *s = xstrdup(spec), *eq = strchr(s, '=');
	char buf[512];
	if (eq)
	{
		*eq = 0;
		snprintf(buf, sizeof buf, "%s %s", s, eq + 1);
	}
	else
		snprintf(buf, sizeof buf, "%s 1", s);
	do_define(buf, "<cmdline>", 0);
}

int main(int argc, char **argv)
{
	const char *in = 0, *outp = 0;
	int show = 0, verify = 0, ptype = 0;
	char *defs[64];
	int nd = 0;
	for (int i = 1; i < argc; i++)
	{
		char *a = argv[i];
		if (!strcmp(a, "-o") && i + 1 < argc)
			outp = argv[++i];
		else if (!strcmp(a, "--version"))
		{
			puts("bpfcc build 2026-11-06: user-declared helpers, hot-reg ranking, r0-relay fusion, jump threading/inversion, store-reload forwarding");
			return 0;
		}
		else if (!strcmp(a, "-S"))
			show = 1;
		else if (!strcmp(a, "-V") || !strcmp(a, "--verify"))
			verify = 1;
		else if (!strcmp(a, "-T") && i + 1 < argc)
			ptype = atoi(argv[++i]);
		else if (!strcmp(a, "-mv2") || !strcmp(a, "-mcpu=v2"))
			use_v2 = 1;
		else if (!strcmp(a, "-legacy-maps"))
			legacy_maps = 1;
		else if (!strncmp(a, "-D", 2))
		{
			char *v = a[2] ? a + 2 : (i + 1 < argc ? argv[++i] : 0);
			if (!v || nd >= 64)
			{
				fprintf(stderr, "bad -D\n");
				return 1;
			}
			defs[nd++] = v;
		}
		else if (!strncmp(a, "-I", 2))
		{
			char *v = a[2] ? a + 2 : (i + 1 < argc ? argv[++i] : 0);
			if (!v || nincdirs >= 32)
			{
				fprintf(stderr, "bad -I\n");
				return 1;
			}
			incdirs[nincdirs++] = v;
		}
		else if (a[0] == '-')
		{
			fprintf(stderr, "unknown option %s\n", a);
			return 1;
		}
		else
			in = a;
	}
	if (!in)
	{
		fprintf(stderr,
				"usage: %s prog.c [-o prog.o] [-S] [-DNAME[=V]] [-Idir] [-mv2] [-legacy-maps] [-V [-T prog_type]]\n",
				argv[0]);
		return 1;
	}
	char *src = read_file(in);
	if (!src)
	{
		perror(in);
		return 1;
	}
	init_types();
	for (int i = 0; i < nd; i++)
		def_macro(defs[i]);
	pp_text(xstrdup(PRELUDE), "<prelude>", 0);
	pp_text(src, in, 0);
	flush();
	Tok eof;
	memset(&eof, 0, sizeof eof);
	eof.file = in;
	eof.line = cur_line;
	PUSH(final_, eof);
	T = final_.p;
	pos = 0;
	parse_top();
	int any = 0;
	for (int i = 0; i < funcs.n; i++)
		if (funcs.p[i]->sec && funcs.p[i]->defined)
		{
			gen_entry(funcs.p[i]);
			any = 1;
		}
	if (!any)
	{
		cur_file = in;
		cur_line = 0;
		die("no entry function: mark programs with SEC(\"...\")");
	}
	if (show)
		for (int i = 0; i < progs.n; i++)
			dis(&progs.p[i]);
	if (outp || !show)
	{
		char def[1024];
		if (!outp)
		{
			snprintf(def, sizeof def, "%s", in);
			char *d = strrchr(def, '.');
			if (d)
				*d = 0;
			strcat(def, ".o");
			outp = def;
		}
		write_elf(outp);
	}
	if (verify)
	{
#ifdef __linux__
		return verify_all(ptype) ? 1 : 0;
#else
		fprintf(stderr, "-V is only supported on Linux\n");
		return 1;
#endif
	}
	(void)ptype;
	return 0;
}
