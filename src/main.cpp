// SPDX-License-Identifier: MIT
// cpp-devmcast-watch — Layer-2 multicast groups from /proc/net/dev_mcast
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o devmcast-watch
// Usage: ./devmcast-watch [options]

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Mutable ANSI palette (--no-color must actually clear it)
// ─────────────────────────────────────────────────────────────────────────────
static std::string C_RESET   = "\x1b[0m";
static std::string C_BOLD    = "\x1b[1m";
static std::string C_DIM     = "\x1b[2m";
static std::string C_RED     = "\x1b[31m";
static std::string C_GREEN   = "\x1b[32m";
static std::string C_YELLOW  = "\x1b[33m";
static std::string C_BLUE    = "\x1b[34m";
static std::string C_CYAN    = "\x1b[36m";
static std::string C_MAGENTA = "\x1b[35m";

static void disable_color() {
  C_RESET = C_BOLD = C_DIM = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_MAGENTA = "";
}

static void enable_color() {
  C_RESET = "\x1b[0m"; C_BOLD = "\x1b[1m"; C_DIM = "\x1b[2m";
  C_RED = "\x1b[31m"; C_GREEN = "\x1b[32m"; C_YELLOW = "\x1b[33m";
  C_BLUE = "\x1b[34m"; C_CYAN = "\x1b[36m"; C_MAGENTA = "\x1b[35m";
}

// ─────────────────────────────────────────────────────────────────────────────
// Model
// ─────────────────────────────────────────────────────────────────────────────
enum class Family { Ipv4, Ipv6, Ieee, Cisco, Other };

static const char* family_name(Family f) {
  switch (f) {
    case Family::Ipv4:  return "ipv4";
    case Family::Ipv6:  return "ipv6";
    case Family::Ieee:  return "ieee";
    case Family::Cisco: return "cisco";
    default:            return "other";
  }
}

static Family family_of(const uint8_t m[6]) {
  if (m[0] == 0x01 && m[1] == 0x00 && m[2] == 0x5e) return Family::Ipv4;
  if (m[0] == 0x33 && m[1] == 0x33) return Family::Ipv6;
  if (m[0] == 0x01 && m[1] == 0x80 && m[2] == 0xc2) return Family::Ieee;
  if (m[0] == 0x01 && m[1] == 0x00 && m[2] == 0x0c) return Family::Cisco;
  return Family::Other;
}

struct McAddr {
  int ifindex = 0;
  std::string iface;
  int refcnt = 0;
  int global_use = 0;
  uint8_t mac[6]{};

  Family family() const { return family_of(mac); }

  std::string mac_str() const {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
  }
};

struct Catalog {
  long ts = 0;
  std::vector<McAddr> groups;
  std::string source;

  std::size_t family_count(Family f) const {
    return static_cast<std::size_t>(
        std::count_if(groups.begin(), groups.end(),
                      [f](const McAddr& g) { return g.family() == f; }));
  }
  std::size_t iface_count() const {
    std::unordered_set<std::string> s;
    for (const auto& g : groups) s.insert(g.iface);
    return s.size();
  }
};

struct Filters {
  std::string iface;
  std::string family;   // ipv4|ipv6|ieee|cisco|other
  bool global_only = false;
  int top = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// Well-known labels (L2 multicast → protocol)
// ─────────────────────────────────────────────────────────────────────────────
struct Known {
  uint8_t mac[6];
  const char* label;
  const char* hint;
};

static const Known kKnown[] = {
  // IPv4 (RFC 1112: 01:00:5e + lower 23 bits)
  {{0x01,0x00,0x5e,0x00,0x00,0x01}, "All Hosts",        "224.0.0.1"},
  {{0x01,0x00,0x5e,0x00,0x00,0x02}, "All Routers",      "224.0.0.2"},
  {{0x01,0x00,0x5e,0x00,0x00,0x05}, "OSPF All SPFs",    "224.0.0.5"},
  {{0x01,0x00,0x5e,0x00,0x00,0x06}, "OSPF DRs",         "224.0.0.6"},
  {{0x01,0x00,0x5e,0x00,0x00,0x09}, "RIP v2",           "224.0.0.9"},
  {{0x01,0x00,0x5e,0x00,0x00,0x0a}, "EIGRP",            "224.0.0.10"},
  {{0x01,0x00,0x5e,0x00,0x00,0x0d}, "PIM",              "224.0.0.13"},
  {{0x01,0x00,0x5e,0x00,0x00,0x12}, "VRRP",             "224.0.0.18"},
  {{0x01,0x00,0x5e,0x00,0x00,0x16}, "IGMPv3",           "224.0.0.22"},
  {{0x01,0x00,0x5e,0x00,0x00,0xfb}, "mDNS",             "224.0.0.251"},
  {{0x01,0x00,0x5e,0x00,0x00,0xfc}, "LLMNR",            "224.0.0.252"},
  {{0x01,0x00,0x5e,0x00,0x01,0x01}, "NTP",              "224.0.1.1"},
  {{0x01,0x00,0x5e,0x7f,0xff,0xfa}, "SSDP",             "239.255.255.250"},
  // IPv6 (RFC 2464: 33:33 + last 32 bits)
  {{0x33,0x33,0x00,0x00,0x00,0x01}, "All Nodes",        "ff02::1"},
  {{0x33,0x33,0x00,0x00,0x00,0x02}, "All Routers",      "ff02::2"},
  {{0x33,0x33,0x00,0x00,0x00,0x16}, "MLDv2",            "ff02::16"},
  {{0x33,0x33,0x00,0x00,0x00,0xfb}, "mDNS",             "ff02::fb"},
  {{0x33,0x33,0x00,0x01,0x00,0x02}, "DHCPv6",           "ff02::1:2"},
  {{0x33,0x33,0x00,0x01,0x00,0x03}, "LLMNR",            "ff02::1:3"},
  // IEEE 802 reserved (01:80:c2:00:00:0x)
  {{0x01,0x80,0xc2,0x00,0x00,0x00}, "STP / Pause",      "01:80:c2:00:00:00"},
  {{0x01,0x80,0xc2,0x00,0x00,0x02}, "LACP",             "01:80:c2:00:00:02"},
  {{0x01,0x80,0xc2,0x00,0x00,0x03}, "802.1X",           "01:80:c2:00:00:03"},
  {{0x01,0x80,0xc2,0x00,0x00,0x0e}, "LLDP",             "01:80:c2:00:00:0e"},
  // Cisco
  {{0x01,0x00,0x0c,0xcc,0xcc,0xcc}, "CDP / VTP",        "01:00:0c:cc:cc:cc"},
  {{0x01,0x00,0x0c,0xcc,0xcc,0xcd}, "PVST+",            "01:00:0c:cc:cc:cd"},
};

static bool mac_eq(const uint8_t a[6], const uint8_t b[6]) {
  return std::memcmp(a, b, 6) == 0;
}

static bool is_solicited_node(const uint8_t m[6]) {
  return m[0] == 0x33 && m[1] == 0x33 && m[2] == 0xff;
}

static std::string solicited_hint(const uint8_t m[6]) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "ff02::1:ff%02x:%02x%02x", m[3], m[4], m[5]);
  return buf;
}

static std::string ipv4_hint(const uint8_t m[6]) {
  // 23-bit mapping: IP = 224.(mac[3]&0x7f).mac[4].mac[5]  (5 bits of group lost)
  char buf[16];
  std::snprintf(buf, sizeof(buf), "224.%u.%u.%u",
                static_cast<unsigned>(m[3] & 0x7f),
                static_cast<unsigned>(m[4]),
                static_cast<unsigned>(m[5]));
  return buf;
}

struct Decoded {
  const char* label;   // may be empty string
  std::string hint;
};

static Decoded decode(const McAddr& g) {
  for (const auto& k : kKnown) {
    if (mac_eq(g.mac, k.mac)) return {k.label, k.hint};
  }
  if (is_solicited_node(g.mac)) return {"solicited-node", solicited_hint(g.mac)};
  if (g.family() == Family::Ipv4) return {"IPv4 mcast", ipv4_hint(g.mac)};
  if (g.family() == Family::Ipv6) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "ff02::%02x%02x:%02x%02x",
                  g.mac[2], g.mac[3], g.mac[4], g.mac[5]);
    return {"IPv6 mcast", std::string(buf)};
  }
  return {"", ""};
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing  /proc/net/dev_mcast
// Format (netdev_mc_seq_show):
//   "%3d %-16s %-5d %-5d %02x%02x%02x%02x%02x%02x\n"
//   ifindex  name  refcnt  global_use  mac(12 hex, no colons)
// ─────────────────────────────────────────────────────────────────────────────
static std::string trim(std::string_view s) {
  auto a = s.find_first_not_of(" \t\r");
  if (a == std::string_view::npos) return {};
  auto b = s.find_last_not_of(" \t\r");
  return std::string(s.substr(a, b - a + 1));
}

static bool parse_mac12(std::string_view hex, uint8_t out[6]) {
  if (hex.size() != 12) return false;
  for (int i = 0; i < 6; ++i) {
    unsigned v = 0;
    auto [p, ec] = std::from_chars(hex.data() + i * 2, hex.data() + i * 2 + 2, v, 16);
    if (ec != std::errc{} || p != hex.data() + i * 2 + 2) return false;
    out[i] = static_cast<uint8_t>(v);
  }
  return true;
}

static bool parse_line(std::string_view raw, McAddr& out) {
  auto hash = raw.find('#');
  if (hash != std::string_view::npos) raw = raw.substr(0, hash);
  auto line = trim(raw);
  if (line.empty()) return false;

  std::istringstream ss{std::string(line)};
  int ifindex = 0, refcnt = 0, glob = 0;
  std::string iface, mac;
  if (!(ss >> ifindex >> iface >> refcnt >> glob >> mac)) return false;
  McAddr g;
  g.ifindex = ifindex;
  g.iface = std::move(iface);
  g.refcnt = refcnt;
  g.global_use = glob;
  if (!parse_mac12(mac, g.mac)) return false;
  out = std::move(g);
  return true;
}

static bool load_catalog(Catalog& c, const std::string& path) {
  std::ifstream in(path);
  if (!in) return false;
  c.groups.clear();
  c.source = path;
  std::string line;
  while (std::getline(in, line)) {
    McAddr g;
    if (parse_line(line, g)) c.groups.push_back(std::move(g));
  }
  return true;
}

static bool load_from_string(Catalog& c, std::string_view blob) {
  c.groups.clear();
  c.source = "<memory>";
  std::istringstream in{std::string(blob)};
  std::string line;
  while (std::getline(in, line)) {
    McAddr g;
    if (parse_line(line, g)) c.groups.push_back(std::move(g));
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo — synthetic dual-stack host (eth0 + wlan0 + br0)
// ─────────────────────────────────────────────────────────────────────────────
static const char* kDemoBlob =
    "# synthetic /proc/net/dev_mcast (demo host, dual-stack + bridge)\n"
    "2    eth0            2     1     01005e000001\n"
    "2    eth0            1     0     01005e000016\n"
    "2    eth0            1     0     01005e0000fb\n"
    "2    eth0            3     1     333300000001\n"
    "2    eth0            1     0     3333ffaabbcc\n"
    "3    wlan0           1     0     01005e000001\n"
    "3    wlan0           1     0     01005e7ffffa\n"
    "3    wlan0           1     0     333300000001\n"
    "3    wlan0           1     0     3333000000fb\n"
    "4    br0             4     1     0180c2000000\n"
    "4    br0             1     0     0180c200000e\n"
    "4    br0             1     0     01000ccccccc\n"
    "4    br0             2     0     01005e000012\n"
    "4    br0             1     0     333300000002\n"
    "# trailing comment + blank line\n"
    "\n"
    "garbage this is not a row\n";

static bool demo_load(Catalog& c) {
  bool ok = load_from_string(c, kDemoBlob);
  c.source = "demo";
  return ok && c.groups.size() == 14;
}

// ─────────────────────────────────────────────────────────────────────────────
// Filters / sort
// ─────────────────────────────────────────────────────────────────────────────
static bool passes(const McAddr& g, const Filters& f) {
  if (!f.iface.empty() && g.iface != f.iface) return false;
  if (!f.family.empty() && family_name(g.family()) != f.family) return false;
  if (f.global_only && g.global_use <= 0) return false;
  return true;
}

static std::vector<const McAddr*> select_rows(const Catalog& c, const Filters& f) {
  std::vector<const McAddr*> rows;
  for (const auto& g : c.groups) if (passes(g, f)) rows.push_back(&g);
  if (f.top > 0) {
    std::stable_sort(rows.begin(), rows.end(),
                     [](const McAddr* a, const McAddr* b) { return a->refcnt > b->refcnt; });
    if (static_cast<int>(rows.size()) > f.top) rows.resize(static_cast<std::size_t>(f.top));
  }
  return rows;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON
// ─────────────────────────────────────────────────────────────────────────────
static std::string json_escape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char ch : s) {
    switch (ch) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': o += "\\r";  break;
      case '\t': o += "\\t";  break;
      default:
        if (ch < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
          o += buf;
        } else {
          o += static_cast<char>(ch);
        }
    }
  }
  return o;
}

static void render_json(std::ostream& os, const Catalog& c) {
  os << "{\n  \"summary\": {\n";
  os << "    \"entries\": " << c.groups.size() << ",\n";
  os << "    \"ifaces\": " << c.iface_count() << ",\n";
  os << "    \"ipv4\": " << c.family_count(Family::Ipv4) << ",\n";
  os << "    \"ipv6\": " << c.family_count(Family::Ipv6) << ",\n";
  os << "    \"ieee\": " << c.family_count(Family::Ieee) << ",\n";
  os << "    \"cisco\": " << c.family_count(Family::Cisco) << ",\n";
  os << "    \"other\": " << c.family_count(Family::Other) << ",\n";
  os << "    \"source\": \"" << json_escape(c.source) << "\"\n";
  os << "  },\n  \"groups\": [\n";
  for (std::size_t i = 0; i < c.groups.size(); ++i) {
    const auto& g = c.groups[i];
    auto d = decode(g);
    os << "    {\"ifindex\": " << g.ifindex
       << ", \"iface\": \"" << json_escape(g.iface) << "\""
       << ", \"refcnt\": " << g.refcnt
       << ", \"global\": " << g.global_use
       << ", \"mac\": \"" << g.mac_str() << "\""
       << ", \"family\": \"" << family_name(g.family()) << "\""
       << ", \"label\": \"" << json_escape(d.label) << "\""
       << ", \"hint\": \"" << json_escape(d.hint) << "\"}";
    os << (i + 1 < c.groups.size() ? ",\n" : "\n");
  }
  os << "  ]\n}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Table render
// ─────────────────────────────────────────────────────────────────────────────
static const char* fam_color(Family f) {
  switch (f) {
    case Family::Ipv4:  return C_YELLOW.c_str();
    case Family::Ipv6:  return C_CYAN.c_str();
    case Family::Ieee:  return C_GREEN.c_str();
    case Family::Cisco: return C_MAGENTA.c_str();
    default:            return C_DIM.c_str();
  }
}

static void render_catalog(const Catalog& c, const Filters& f, bool /*unused*/) {
  auto rows = select_rows(c, f);
  std::cout << C_BOLD << "-- device multicast  /proc/net/dev_mcast --" << C_RESET << "\n";
  std::cout << C_DIM << "source: " << C_RESET << c.source
            << C_DIM << "  shown " << C_RESET << rows.size()
            << C_DIM << " / " << C_RESET << c.groups.size() << "\n";
  std::cout << "  " << C_DIM << "entries " << C_RESET << C_BOLD << c.groups.size() << C_RESET
            << "  " << C_DIM << "ifaces " << C_RESET << c.iface_count()
            << "  " << C_YELLOW << "ipv4 " << c.family_count(Family::Ipv4) << C_RESET
            << "  " << C_CYAN << "ipv6 " << c.family_count(Family::Ipv6) << C_RESET
            << "  " << C_GREEN << "ieee " << c.family_count(Family::Ieee) << C_RESET
            << "  " << C_MAGENTA << "cisco " << c.family_count(Family::Cisco) << C_RESET
            << "\n";

  std::cout << C_DIM
            << "  IFACE            IDX  REF  G  MAC               FAMILY  LABEL            HINT\n"
            << C_RESET;
  for (const auto* pg : rows) {
    const auto& g = *pg;
    auto d = decode(g);
    char idx[8], ref[8], gl[4];
    std::snprintf(idx, sizeof(idx), "%3d", g.ifindex);
    std::snprintf(ref, sizeof(ref), "%3d", g.refcnt);
    std::snprintf(gl, sizeof(gl), "%1d", g.global_use);
    std::string iface = g.iface;
    if (iface.size() < 16) iface.append(16 - iface.size(), ' ');
    std::string label = d.label;
    if (label.size() < 16) label.append(16 - label.size(), ' ');
    if (label.size() > 16) label.resize(16);
    std::cout << "  " << C_BOLD << iface << C_RESET
              << " " << idx
              << "  " << (g.refcnt >= 3 ? C_YELLOW : "") << ref << C_RESET
              << "  " << (g.global_use ? C_GREEN : C_DIM) << gl << C_RESET
              << "  " << g.mac_str()
              << "  " << fam_color(g.family()) << family_name(g.family()) << C_RESET;
    if (std::strlen(family_name(g.family())) < 6)
      std::cout << std::string(6 - std::strlen(family_name(g.family())), ' ');
    std::cout << "  " << label
              << " " << C_DIM << d.hint << C_RESET
              << "\n";
  }
  std::cout << C_GREEN << "  -- " << rows.size() << " groups shown --" << C_RESET << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Selftest
// ─────────────────────────────────────────────────────────────────────────────
static int g_pass = 0, g_fail = 0;

static void t_check(bool cond, const char* msg) {
  if (cond) {
    ++g_pass;
    std::cout << "  PASS  " << msg << "\n";
  } else {
    ++g_fail;
    std::cout << "  FAIL  " << msg << "\n";
  }
}

static int run_selftest() {
  std::cout << "-- selftest: family classification --\n";
  {
    uint8_t a[6] = {0x01,0x00,0x5e,0x00,0x00,0x01};
    uint8_t b[6] = {0x33,0x33,0x00,0x00,0x00,0x01};
    uint8_t c[6] = {0x01,0x80,0xc2,0x00,0x00,0x0e};
    uint8_t d[6] = {0x01,0x00,0x0c,0xcc,0xcc,0xcc};
    uint8_t e[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    t_check(family_of(a) == Family::Ipv4, "01:00:5e → ipv4");
    t_check(family_of(b) == Family::Ipv6, "33:33 → ipv6");
    t_check(family_of(c) == Family::Ieee, "01:80:c2 → ieee");
    t_check(family_of(d) == Family::Cisco, "01:00:0c → cisco");
    t_check(family_of(e) == Family::Other, "broadcast → other");
    t_check(std::string(family_name(Family::Ipv4)) == "ipv4", "family_name ipv4");
    t_check(std::string(family_name(Family::Ipv6)) == "ipv6", "family_name ipv6");
  }

  std::cout << "-- selftest: MAC parser --\n";
  {
    uint8_t m[6]{};
    t_check(parse_mac12("01005e000001", m) && m[0]==0x01 && m[2]==0x5e && m[5]==0x01,
            "parse 01005e000001");
    t_check(parse_mac12("3333FFAABBCC", m) && m[2]==0xff && m[5]==0xcc,
            "parse mixed-case hex");
    t_check(!parse_mac12("01005e00000", m), "reject 11 hex chars");
    t_check(!parse_mac12("01005e000001zz", m), "reject 14 hex chars");
    t_check(!parse_mac12("gg005e000001", m), "reject non-hex");
  }

  std::cout << "-- selftest: line parser + comments --\n";
  {
    McAddr g;
    t_check(parse_line("2    eth0            1     0     333300000001", g)
            && g.ifindex == 2 && g.iface == "eth0" && g.refcnt == 1
            && g.global_use == 0 && g.mac[0]==0x33 && g.mac[5]==0x01,
            "canonical kernel line");
    t_check(parse_line("  2 eth0 2 1 01005e000001  # All Hosts", g)
            && g.refcnt == 2 && g.global_use == 1 && g.family() == Family::Ipv4,
            "inline # comment stripped");
    t_check(!parse_line("# whole-line comment", g), "whole-line comment skipped");
    t_check(!parse_line("", g), "empty line skipped");
    t_check(!parse_line("garbage this is not a row", g), "garbage skipped");
    t_check(!parse_line("2 eth0 1 0 nothex", g), "bad mac skipped");
  }

  std::cout << "-- selftest: decode well-known --\n";
  {
    McAddr g{};
    uint8_t a[6] = {0x01,0x00,0x5e,0x00,0x00,0x01}; std::memcpy(g.mac, a, 6);
    auto d = decode(g);
    t_check(std::string(d.label) == "All Hosts" && d.hint == "224.0.0.1", "All Hosts");
    uint8_t b[6] = {0x33,0x33,0x00,0x00,0x00,0x01}; std::memcpy(g.mac, b, 6);
    d = decode(g);
    t_check(std::string(d.label) == "All Nodes" && d.hint == "ff02::1", "All Nodes");
    uint8_t c[6] = {0x33,0x33,0xff,0xaa,0xbb,0xcc}; std::memcpy(g.mac, c, 6);
    d = decode(g);
    t_check(std::string(d.label) == "solicited-node" && d.hint.find("ff02::1:ff") == 0,
            "solicited-node prefix");
    uint8_t e[6] = {0x01,0x80,0xc2,0x00,0x00,0x0e}; std::memcpy(g.mac, e, 6);
    d = decode(g);
    t_check(std::string(d.label) == "LLDP", "LLDP");
    uint8_t f[6] = {0x01,0x00,0x5e,0x00,0x00,0x16}; std::memcpy(g.mac, f, 6);
    d = decode(g);
    t_check(std::string(d.label) == "IGMPv3" && d.hint == "224.0.0.22", "IGMPv3");
    uint8_t h[6] = {0x01,0x00,0x5e,0x01,0x02,0x03}; std::memcpy(g.mac, h, 6);
    d = decode(g);
    t_check(std::string(d.label) == "IPv4 mcast" && d.hint == "224.1.2.3", "generic IPv4 23-bit");
  }

  std::cout << "-- selftest: demo blob --\n";
  {
    Catalog d;
    t_check(demo_load(d), "demo loads 14 groups");
    t_check(d.groups.size() == 14, "demo size 14");
    t_check(d.iface_count() == 3, "demo 3 ifaces (eth0/wlan0/br0)");
    t_check(d.family_count(Family::Ipv4) == 6, "demo 6 ipv4");
    t_check(d.family_count(Family::Ipv6) == 5, "demo 5 ipv6");
    t_check(d.family_count(Family::Ieee) == 2, "demo 2 ieee");
    t_check(d.family_count(Family::Cisco) == 1, "demo 1 cisco");
    t_check(d.groups[0].iface == "eth0" && d.groups[0].family() == Family::Ipv4,
            "demo first eth0 ipv4");
    t_check(d.groups[3].family() == Family::Ipv6, "demo All Nodes ipv6");
    t_check(is_solicited_node(d.groups[4].mac), "demo solicited-node on eth0");
  }

  std::cout << "-- selftest: /proc/net/dev_mcast real --\n";
  {
    Catalog c;
    bool ok = load_catalog(c, "/proc/net/dev_mcast");
    t_check(ok, "/proc/net/dev_mcast opens");
    if (ok) {
      t_check(!c.groups.empty(), "kernel exposes at least 1 L2 group");
      t_check(std::all_of(c.groups.begin(), c.groups.end(),
                          [](const McAddr& g) { return !g.iface.empty() && g.ifindex > 0; }),
              "every row has iface + ifindex");
      bool some_known = false;
      for (const auto& g : c.groups) {
        auto d = decode(g);
        if (std::string(d.label) == "All Hosts" || std::string(d.label) == "All Nodes")
          some_known = true;
      }
      t_check(some_known, "host has All Hosts and/or All Nodes");
    }
  }

  std::cout << "-- selftest: filters + --top sort --\n";
  {
    Catalog d;
    demo_load(d);
    Filters f;
    f.iface = "eth0";
    std::size_t n = 0;
    for (const auto& g : d.groups) if (passes(g, f)) ++n;
    t_check(n == 5, "iface=eth0 keeps 5");
    f.iface.clear();
    f.family = "ieee";
    n = 0;
    for (const auto& g : d.groups) if (passes(g, f)) ++n;
    t_check(n == 2, "family=ieee keeps 2");
    f.family.clear();
    f.global_only = true;
    n = 0;
    for (const auto& g : d.groups) if (passes(g, f)) ++n;
    t_check(n == 3, "global_only keeps 3");
    f.global_only = false;
    f.top = 5;
    auto rows = select_rows(d, f);
    t_check(rows.size() == 5, "--top 5 yields 5 rows");
    bool desc = rows.size() == 5 &&
                rows[0]->refcnt >= rows[1]->refcnt &&
                rows[1]->refcnt >= rows[2]->refcnt &&
                rows[2]->refcnt >= rows[3]->refcnt;
    t_check(desc, "--top sorts by refcnt descending (ties allowed)");
    t_check(rows[0]->refcnt == 4, "top entry is br0 STP refcnt=4");
  }

  std::cout << "-- selftest: JSON + --no-color hygiene --\n";
  {
    Catalog d;
    demo_load(d);
    d.ts = 0;
    std::ostringstream os;
    render_json(os, d);
    std::string j = os.str();
    t_check(j.find("\"summary\"") != std::string::npos, "json has summary");
    t_check(j.find("\"groups\"") != std::string::npos, "json has groups");
    t_check(j.find("\"family\": \"ipv4\"") != std::string::npos, "json family ipv4 quoted");
    t_check(j.find("\"mac\": \"01:00:5e:00:00:01\"") != std::string::npos, "json mac All Hosts");
    t_check(j.find("\"label\": \"LLDP\"") != std::string::npos, "json LLDP label");
    t_check(j.find("{summary:") == std::string::npos, "json keys always quoted");

    disable_color();
    Filters f;
    std::ostringstream o2;
    std::streambuf* old = std::cout.rdbuf(o2.rdbuf());
    render_catalog(d, f, false);
    std::cout.rdbuf(old);
    std::string out = o2.str();
    t_check(out.find("\x1b[") == std::string::npos, "no ANSI codes with --no-color");
    t_check(out.find("eth0") != std::string::npos, "table still prints iface");
    enable_color();
  }

  std::cout << "-- selftest: json escapes --\n";
  {
    t_check(json_escape("a\"b") == "a\\\"b", "quote escaped");
    t_check(json_escape("a\\b") == "a\\\\b", "backslash escaped");
    t_check(json_escape("plain") == "plain", "plain unchanged");
  }

  std::cout << "selftest: " << g_pass << " passed, " << g_fail << " failed\n";
  return g_fail == 0 ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_help() {
  std::cout <<
    "devmcast-watch — Layer-2 multicast groups (/proc/net/dev_mcast)\n"
    "\n"
    "Usage: devmcast-watch [options]\n"
    "\n"
    "  --iface IFACE      only groups on IFACE (e.g. eth0)\n"
    "  --family FAM       ipv4 | ipv6 | ieee | cisco | other\n"
    "  --global           only addresses with global_use > 0\n"
    "  --top N            top N by refcnt (descending, ties allowed)\n"
    "  --watch N          refresh every N seconds\n"
    "  --json             machine-readable output\n"
    "  --demo             synthetic dual-stack + bridge host\n"
    "  --file PATH        parse a dump instead of /proc\n"
    "  --no-color         disable ANSI colors\n"
    "  --selftest         run self-tests and exit\n"
    "  -h, --help         this help\n";
}

int main(int argc, char** argv) {
  Filters f;
  bool color_flag = true;
  bool demo = false;
  bool json = false;
  int watch = 0;
  std::string file;
  for (int i = 1; i < argc; ++i) {
    std::string_view a{argv[i]};
    auto next = [&](std::string_view name) -> std::optional<std::string> {
      if (i + 1 >= argc) {
        std::cerr << "error: " << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[++i]);
    };
    if (a == "--iface")      { auto v = next(a); if (!v) return 2; f.iface = *v; }
    else if (a == "--family"){ auto v = next(a); if (!v) return 2; f.family = *v; }
    else if (a == "--file")  { auto v = next(a); if (!v) return 2; file = *v; }
    else if (a == "--top")   { auto v = next(a); if (!v) return 2; f.top = std::atoi(v->c_str()); }
    else if (a == "--watch") { auto v = next(a); if (!v) return 2; watch = std::atoi(v->c_str()); }
    else if (a == "--global")    f.global_only = true;
    else if (a == "--demo")      demo = true;
    else if (a == "--json")      json = true;
    else if (a == "--no-color")  color_flag = false;
    else if (a == "--selftest")  return run_selftest();
    else if (a == "-h" || a == "--help") { print_help(); return 0; }
    else { std::cerr << "error: unknown option '" << a << "' (see --help)\n"; return 2; }
  }

  if (!color_flag) disable_color();

  std::string source = file.empty() ? "/proc/net/dev_mcast" : file;

  auto load_one = [&](Catalog& cat) -> bool {
    cat.ts = std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
    return demo ? demo_load(cat) : load_catalog(cat, source);
  };

  if (watch > 0) {
    for (;;) {
      Catalog cur;
      if (!load_one(cur)) {
        std::cerr << "error: cannot read " << source << "\n";
        return 1;
      }
      std::cout << "\x1b[2J\x1b[H";
      if (json) render_json(std::cout, cur);
      else render_catalog(cur, f, false);
      std::cout << std::flush;
      std::this_thread::sleep_for(std::chrono::seconds(watch));
    }
  }

  Catalog cat;
  if (!load_one(cat)) {
    std::cerr << "error: cannot read " << source << "\n";
    return 1;
  }
  if (json) render_json(std::cout, cat);
  else render_catalog(cat, f, false);
  return 0;
}
