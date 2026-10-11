const rulesets = [
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list', 'DIRECT'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/ChinaOnly.list', 'DIRECT'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/UnBan1.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/zsokami/ACL4SSR/main/BanProgramAD1.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list', '💩 ‍广告'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/BilibiliHMT.list', '📺 ‍B站'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Bilibili.list', '📺 ‍B站'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list', '🤖 ‍AI'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/UnBan.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/ProxyGFWlist.list', '✈️ ‍起飞'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list', '🛩️ ‍墙内'],
  ['https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list', '🛩️ ‍墙内'],
]

const supported_types = new Set([
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'GEOSITE',
  'IP-CIDR',
  'IP-CIDR6',
  'IP-SUFFIX',
  'IP-ASN',
  'GEOIP',
])

Deno.writeTextFileSync(
  'netlify/edge-functions/main/rules.ts',
  `export const RULES = \`rules:
${
    (await Promise.all(rulesets.map(async ([url, name]) =>
      (await (await fetch(url)).text())
        .match(/^[^#\s].*/mg)
        ?.map((x) => x.split(','))
        .filter((x) => supported_types.has(x[0]))
        .map((x) => {
          x.splice(2, 0, name)
          return '- ' + x.join(',')
        }) ?? []
    ))).flat().join('\n')
  }
- GEOIP,CN,🛩️ ‍墙内
- MATCH,🌐 ‍未知站点
\``,
)
