#include<bits/stdc++.h>

using namespace std;
typedef long long LL;
#define go(u) for(int i = head[u], v = e[i].to; i; i=e[i].lst, v=e[i].to)
#define rep(i, a, b) for(int i = a; i <= b; ++i)
#define pb push_back
#define re(x) memset(x, 0, sizeof x)

inline int gi() {
    int x = 0, f = 1;
    char ch = getchar();
    while (!isdigit(ch)) {
        if (ch == '-') f = -1;
        ch = getchar();
    }
    while (isdigit(ch)) {
        x = (x << 3) + (x << 1) + ch - 48;
        ch = getchar();
    }
    return x * f;
}

template<typename T>
inline bool Max(T &a, T b) { return a < b ? a = b, 1 : 0; }

template<typename T>
inline bool Min(T &a, T b) { return a > b ? a = b, 1 : 0; }

const int N = 7e4 + 7, inf = 0x3f3f3f3f;
int n, rt, edc, sn;
int mn[N], deg[N], ans[N], mxs[N], head[N], son[N];
bool vis[N];

struct edge {
    int lst, to;

    edge() {}

    edge(int lst, int to) : lst(lst), to(to) {}
} e[N << 1];

void Add(int a, int b) {
    ++deg[a], ++deg[b];
    e[++edc] = edge(head[a], b), head[a] = edc;
    e[++edc] = edge(head[b], a), head[b] = edc;
}

void bfs() {
    queue<int> Q;
    memset(mn, 0x3f, sizeof mn);
    rep(i, 1, n) if (deg[i] == 1) {
            mn[i] = 0, Q.push(i);
        }
    while (!Q.empty()) {
        int u = Q.front();
        Q.pop();
        go(u)
            if (mn[v] == inf) {
                mn[v] = mn[u] + 1;
                Q.push(v);
            }
    }
}

int tp;
typedef pair<int, int> pii;
#define mp make_pair
pii suf[N];

void getrt(int u, int fa) {
    mxs[u] = 0;
    son[u] = 1;
    go(u)
        if (!vis[v] && v ^ fa) {
            getrt(v, u);
            son[u] += son[v];
            Max(mxs[u], son[v]);
        }
    Max(mxs[u], sn - son[u]);
    if (mxs[u] < mxs[rt]) rt = u;
}

void getdep(int u, int fa, int dis) {
    if (mn[u] - dis > 0) suf[++tp] = mp(mn[u] - dis, 2 - deg[u]);
    go(u)
        if (!vis[v] && v ^ fa) {
            getdep(v, u, dis + 1);
        }
}

void getans(int u, int fa, int dis, int f) {
    int gg = upper_bound(suf + 1, suf + 1 + tp, mp(dis, inf)) - suf;
    if (gg != tp + 1)
        ans[u] += f * suf[gg].second;
    go(u)
        if (!vis[v] && v ^ fa) {
            getans(v, u, dis + 1, f);
        }
}

void solve(int u) {
    vis[u] = 1;
    tp = 0;
    getdep(u, 0, 0);
    sort(suf + 1, suf + 1 + tp);
    for (int j = tp - 1; j >= 1; --j) suf[j].second += suf[j + 1].second;
    getans(u, 0, 0, 1);

    go(u)
        if (!vis[v]) {
            tp = 0;
            getdep(v, u, 1);
            sort(suf + 1, suf + 1 + tp);
            for (int j = tp - 1; j >= 1; --j) suf[j].second += suf[j + 1].second;
            getans(v, u, 1, -1);
        }

    int old = sn;
    go(u)
        if (!vis[v]) {
            if (son[v] > son[u])
                sn = old - son[u];
            else
                sn = son[v];
            rt = 0, getrt(v, u), solve(rt);
        }
}

int main() {
    n = gi();
    rep(i, 1, n - 1) Add(gi(), gi());
    bfs();
    sn = n, mxs[rt = 0] = n + 1, getrt(1, 0), solve(rt);
    rep(i, 1, n) printf("%d\n", deg[i] == 1 ? 1 : 2 - ans[i]);
    return 0;
}