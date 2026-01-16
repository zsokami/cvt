export { VERSION } from './version.ts'
export { RULES } from './rules.ts'

export const DEFAULT_UDP = true
export const DEFAULT_SCV = true
export const DEFAULT_CLIENT_FINGERPRINT = 'chrome'
export const DEFAULT_GRPC_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'

export const TYPES_OLD_CLASH_SUPPORTED = new Set([
  'http',
  'socks5',
  'ss',
  'ssr',
  'snell',
  'vmess',
  'vless',
  'trojan',
  'wireguard',
])
export const CIPHERS_OLD_CLASH_SUPPORTED = {
  'ss': new Set([
    'dummy',
    'rc4-md5',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
    'aes-128-cfb',
    'aes-192-cfb',
    'aes-256-cfb',
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'chacha20-ietf',
    'xchacha20',
    'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305',
  ]),
  'ssr': new Set([
    'dummy',
    'rc4-md5',
    'aes-128-ctr',
    'aes-192-ctr',
    'aes-256-ctr',
    'aes-128-cfb',
    'aes-192-cfb',
    'aes-256-cfb',
    'chacha20-ietf',
    'xchacha20',
  ]),
}

export const RE_EXCLUDE =
  /Data Left|Remain:|Traffic:|Expir[ey]|Reset|(?:\d[\d.]*\s*[MG]B[^\dA-Za-z]+|[:：]\s*)\d[\d.]*\s*GB(?![\dA-Za-z])|剩[余餘]流量|流量：|[到过過效]期|[时時][间間]|重置|分割线|残り使用容量|残りデータ通信量|有効期限|リセット|🔰 (?:ID|HSD|SNI):|📝 Gói:/
export const RE_EMOJI: [string, RegExp, RegExp][] = String
  .raw`🇺🇸,USA?|UMI?,美[国國]|华盛顿|波特兰|达拉斯|俄勒冈|凤凰城|菲尼克斯|费利蒙|弗里蒙特|硅谷|旧金山|拉斯维加斯|洛杉|圣何塞|圣荷西|圣塔?克拉拉|西雅图|芝加哥|哥伦布|纽约|阿什本|纽瓦克|丹佛|加利福尼亚|弗吉尼亚|马纳萨斯|俄亥俄|得克萨斯|[佐乔]治亚|亚特兰大|佛罗里达|迈阿密,America|United[^a-z]*States|Washington|Portland|Dallas|Oregon|Phoenix|Fremont|Valley|Francisco|Vegas|Los[^a-z]*Angeles|San[^a-z]*Jose|Santa[^a-z]*Clara|Seattle|Chicago|Columbus|York|Ashburn|Newark|Denver|California|Virginia|Manassas|Ohio|Texas|Atlanta|Florida|Miami
🇭🇰,HKG?|CMI|HGC|HKT|HKBN|WTT|PCCW,香港,Hong
🇯🇵,JPN?,日本|东京|大阪|名古屋|埼玉|福冈,Japan|Tokyo|Osaka|Nagoya|Saitama|Fukuoka
🇸🇬,SGP?,新加坡|[狮獅]城,Singapore
🇹🇼,TWN?|CHT|HiNet,[台臺][湾灣北]|新[北竹]|彰化|高雄,Taiwan|Taipei|Hsinchu|Changhua|Kaohsiung
🇷🇺,RUS?,俄[国國]|俄[罗羅]斯|莫斯科|圣彼得堡|西伯利亚|伯力|哈巴罗夫斯克,Russia|Moscow|Peters?burg|Siberia|Khabarovsk
🇬🇧,UK|GBR?,英[国國]|英格兰|伦敦|加的夫|曼彻斯特|伯克郡,Kingdom|England|London|Cardiff|Manchester|Berkshire
🇨🇦,CAN?,加拿大|[枫楓][叶葉]|多伦多|蒙特利尔|温哥华,Canada|Toronto|Montreal|Vancouver
🇫🇷,FRA?,法[国國]|巴黎|马赛|斯特拉斯堡,France|Paris|Marseille|Marselha|Strasbourg
🇰🇵,KP|PRK,朝[鲜鮮],North[^a-z]*Korea
🇰🇷,KO?R,[韩韓][国國]|首尔|春川,Korea|Seoul|Chuncheon
🇮🇪,IE|IRL,爱尔兰|都柏林,Ireland|Dublin
🇩🇪,DEU?,德[国國]|法兰克福|柏林|杜塞尔多夫,German|Frankfurt|Berlin|D[üu]sseldorf
🇮🇩,IDN?,印尼|印度尼西亚|雅加达,Indonesia|Jakarta
🇮🇳,IND?,印度|孟买|加尔各答|贾坎德|泰米尔纳德|海得拉巴|班加罗尔,India|Mumbai|Kolkata|Jharkhand|Tamil|Hyderabad|Bangalore
🇲🇲,MMR?|YGN,缅甸|[内奈]比[都多]|仰光,Myanmar|Naypyidaw|Nay[^a-z]*Pyi[^a-z]*Taw|Yangon|Rangoon
🇮🇱,IL|ISR,以色列|耶路撒冷,Israel|Jerusalem|Yerushalayim
🇦🇺,AUS?,澳大利[亚亞]|澳洲|悉尼|墨尔本|布里斯[班本],Australia|Sydney|Melbourne|Brisbane
🇦🇪,AR?E|UAE,阿联酋|迪拜|阿布扎比|富查伊拉,Emirates|Dubai|Dhabi|Fujairah
🇧🇦,BA|BIH,波黑|波[士斯]尼亚|[黑赫]塞哥维[纳那]|特拉夫尼克,Bosnia|Herzegovina|Travnik
🇧🇷,BRA?,巴西|圣保罗|维涅杜,Brazil|Paulo|Vinhedo
🇲🇴,MO|MAC|CTM,澳[门門],Maca[uo]
🇿🇦,ZAF?,南非|约(?:翰内斯)?堡,Africa|Johannesburg
🇨🇭,CHE?,瑞士|苏黎世|休伦堡|许嫩贝格,Switzerland|Zurich|H[üu]e?nenberg
🇸🇲,SMR?,圣[马玛][力丽][诺络],San[^a-z]*Marino
🇬🇶,GN?Q,赤道几内亚,Equatorial[^a-z]*Guinea
🇫🇮,FIN?,芬兰|赫尔辛基,Finland|Helsinki
🇹🇭,THA?,泰国|曼谷,Thailand|Bangkok
🇲🇽,ME?X,墨西哥|克雷塔罗,Mexico|Queretaro
🇸🇪,SW?E,瑞典|斯德哥尔摩,Sweden|Stockholm
🇹🇷,TU?R,土耳其|伊斯坦布尔,Turkey|Istanbul
🇸🇦,SAU?,沙特|吉达|利雅得,Arabia|J[eu]dda|Riyadh
🇱🇰,LKA?,斯里兰卡|[科哥可]伦坡,Sri[^a-z]*Lanka|Colombo
🇦🇹,AU?T,奥地利|维也纳,Austria|Vienna
🇴🇲,OMN?,阿曼|马斯喀特,Oman|Muscat
🇪🇸,ESP?,西班牙|马德里|巴塞罗那|[巴瓦]伦西亚,Spain|Madrid|Barcelona|Valencia
🇩🇴,DOM?,多[米明]尼加|圣多明[各哥戈],Dominican|Santo[^a-z]*Domingo
🇱🇮,LIE?,列支敦[士斯]登|瓦杜兹,Liechtenstein|Vaduz
🇧🇴,BOL?,玻利维亚|拉巴斯,Bolivia|La[^a-z]*Paz
🇩🇿,DZA?,阿尔及利亚|阿尔及尔,Algeria|Algiers
🇧🇾,BY|BLR,白俄?罗斯|明斯克,Belarus|Minsk
🇧🇸,BH?S,巴哈马|拿[骚索],Bahamas|Nassau
🇲🇹,ML?T,马耳他|瓦莱塔,Malta|Valletta
🇸🇮,SI|SVN,斯洛文尼亚|卢布尔雅那,Slovenia|Ljubljana
🇳🇱,NLD?,荷兰|阿姆斯特丹,Netherlands|Amsterdam
🇪🇪,EE|EST,爱沙尼亚|塔林,Estonia|Tallinn
🇷🇴,ROU?,罗马[尼利]亚|布加勒斯特,Romania|Bucharest
🇮🇹,ITA?,意大利|米兰|罗马|拉齐奥,Italy|Milan|Rome|Lazio
🇱🇺,LUX?,卢森堡,Luxembo?urg
🇵🇭,PHL?,菲律宾|马尼拉,Philippines|Manila
🇺🇦,UA|UKR,乌克兰|基辅,Ukraine|Kyiv|Kiev
🇦🇿,AZE?,阿塞拜疆,Azerbaijan
🇰🇬,KGZ?,吉尔吉斯斯坦,Kyrgyzstan
🇰🇿,KA?Z,哈萨克斯坦|阿斯塔纳,Kazakhstan|Astana
🇦🇬,AT?G,安提瓜和巴布达,Antigua
🇹🇲,TK?M,土库曼,Turkmenistan
🇦🇫,AFG?,阿富汗,Afghanistan
🇸🇧,SL?B,所罗门群岛,Solomon
🇷🇸,RS|SRB,塞尔维亚|贝尔格莱德,Serbia|Belgrade
🇺🇿,UZB?,乌兹别克斯坦,Uzbekistan
🇦🇷,ARG?,阿根廷|布宜诺,Argentina|Buenos
🇲🇰,MKD?,前南斯拉夫|马其顿|北马|斯科普里,Macedonia|Skopje
🇸🇰,SV?K,斯洛伐克|[布伯]拉[迪第提]斯拉[发瓦法],Slovensko|Bratislava
🇻🇪,VEN?,委内瑞拉|[加卡]拉[加卡]斯,Venezuela|Caracas
🇬🇱,GR?L,格[陵林]兰|努克,Greenland|Nuuk
🇵🇸,PSE?,巴勒斯坦,Palestine
🇧🇬,BGR?,保加利亚|索[非菲]亚,Bulgaria|Sofia
🇨🇴,COL?,哥伦比亚|波哥大,Colombia|Bogot[áa]
🇬🇮,GIB?,直布罗陀,Gibraltar
🇬🇹,GTM?,危地马拉,Guatemala
🇦🇶,AQ|ATA,南极,Antarctica
🇲🇪,MN?E,黑山|波德戈里察,Montenegro|Podgorica
🇿🇼,ZWE?,津巴布韦,Zimbabwe
🇰🇭,KHM?,柬埔寨|金边,Cambodia|Phnom[^a-z]*Penh
🇱🇹,LTU?,立陶宛|维尔纽斯,Lietuvos|Vilnius
🇧🇲,BMU?,百慕大,Bermuda
🇫🇴,FR?O,法罗群岛,Faroe
🇲🇳,MNG?,蒙古|乌兰巴托,Mongolia|Ulaanbaatar
🇲🇾,MYS?,马来|吉隆坡,Malaysia|Kuala
🇵🇰,PA?K,巴基斯坦|卡拉奇,Pakistan|Karachi
🇵🇹,PR?T,葡萄牙|里斯本|葡京,Portugal|Lisbon
🇸🇴,SOM?,索马里,Somalia
🇦🇼,AB?W,阿鲁巴,Aruba
🇩🇰,DN?K,丹麦|哥本哈根,Denmark|Copenhagen
🇮🇸,ISL?,冰岛|雷克雅[未维]克,Iceland|Reykjav[íi]k
🇦🇱,ALB?,阿尔巴尼亚|地拉那,Albania|Tirana
🇧🇪,BEL?,比利时|布鲁塞尔,Belgium|Brussels
🇬🇪,GEO?,格鲁吉亚|第比利斯,Georgia|Tbilisi
🇭🇷,HRV?,克罗地亚|萨格勒布,Croatia|Zagreb
🇭🇺,HUN?,匈牙利|布达佩斯,Hungary|Budapest
🇲🇩,MDA?,摩尔多瓦|基希讷乌,Moldova|Chi[șs]in[ăa]u
🇳🇬,NGA?,尼日利亚|拉各斯,Nigeria|Lagos
🇳🇿,NZL?,新西兰|奥克兰,Zealand|Auckland
🇧🇧,BR?B,巴巴多斯,Barbados
🇹🇳,TU?N,突尼斯,Tunisia
🇺🇾,UR?Y,乌拉圭|蒙得维的亚,Uruguay|Montevideo
🇻🇳,VNM?,越南|河内,Vietnam|Hanoi
🇪🇨,ECU?,厄瓜多尔|基多,Ecuador|Quito
🇲🇦,MAR?,摩洛哥|拉巴特,Morocco|Rabat
🇦🇲,AR?M,亚美尼亚|埃里温|耶烈万,Armenia|Yerevan
🇵🇱,PO?L,波兰|华沙,Poland|Warsaw
🇨🇾,CYP?,塞浦路斯|尼科西亚,Cyprus|Nicosia
🇪🇺,EUE?,欧[洲盟],Euro
🇬🇷,GRC?,希腊|雅典,Greece|Athens
🇯🇴,JOR?,约旦,Jordan
🇱🇻,LVA?,拉脱维亚|里加,Latvia|Riga
🇳🇴,NOR?,挪威|奥斯陆,Norway|Oslo
🇵🇦,PAN?,巴拿马,Panama
🇵🇷,PRI?,波多黎各,Puerto
🇧🇩,BG?D,孟加拉|达卡,Bengal|Dhaka
🇧🇳,BR?N,[文汶]莱,Brunei
🇧🇿,BL?Z,伯利兹,Belize
🇧🇹,BTN?,不丹,Bhutan
🇨🇱,CH?L,智利|圣地亚哥,Chile|Santiago
🇨🇷,CRI?,哥斯达黎加,Costa
🇨🇿,CZE?,捷克|布拉格,Czech|Prague
🇪🇬,EGY?,埃及|开罗,Egypt|Cairo
🇰🇪,KEN?,肯尼亚|内罗[毕比],Kenya|Nairobi
🇳🇵,NPL?,尼泊尔|加德满都,Nepal|Kathmandu
🇮🇲,IMN?,马恩岛|曼岛|道格拉斯,Isle[^a-z]*of[^a-z]*Man|Mann|Douglas
🇻🇦,VAT?,梵蒂冈,Vatican
🇮🇷,IRN?,伊朗|德黑兰,Iran|Tehran
🇵🇪,PER?,秘鲁|利马,Peru|Lima
🇱🇦,LAO?,老挝|寮国|万象|永珍,Lao|Vientiane
🇦🇩,AN?D,安道尔,Andorra
🇲🇨,MCO?,摩纳哥,Monaco
🇷🇼,RWA?,卢旺达,Rwanda
🇹🇱,TL,东帝汶,Timor
🇦🇴,AG?O,安哥拉,Angola
🇶🇦,QAT?,卡塔尔|多哈,Qatar|Doha
🇱🇾,LB?Y,利比亚,Libya
🇧🇭,BHR?,巴林|麦纳麦,Bahrain|Manama
🇾🇪,YEM?,也门,Yemen
🇸🇩,SDN?,苏丹,Sudan
🇨🇺,CUB?,古巴,Cuba
🇲🇱,MLI?,马里,Mali
🇫🇯,FJI?,斐济,Fiji`.split('\n').map((x) => {
  const [flag, code, zh, en] = x.split(',')
  return [flag, new RegExp(zh, 'g'), new RegExp(String.raw`(?<![\da-z.])(?:${code})(?!\d*[a-z])|${en}`, 'ig')]
})
export const RE_EMOJI_SINGLE: [string, RegExp][] = String.raw`🇺🇸,美
🇩🇪,[中京沪滬申广廣深莞苏蘇杭厦廈海光川]德|德(?![\u4E00-\u9FFF])
🇷🇺,[中京沪滬申广廣深莞苏蘇杭厦廈海光川]俄|俄(?![\u4E00-\u9FFF])
🇮🇳,[中京沪滬申广廣深莞苏蘇杭厦廈海光川]印|印(?![\u4E00-\u9FFF])
🇰🇷,[韩韓]
🇯🇵,[中京沪滬申广廣深莞苏蘇杭厦廈海光川]日|(?<![\d\u4E00-\u9FFF])日(?![\u4E00-\u9FFF])
🇸🇬,[中京沪滬申广廣深莞苏蘇杭厦廈海光川]新|(?<![\u4E00-\u9FFF])新(?![\u4E00-\u9FFF])
🇹🇼,[中京沪滬申广廣深莞苏蘇杭厦廈海光川][台臺]|[台臺](?![\u4E00-\u9FFF])
🇭🇰,港`.split('\n').map((x) => {
  const [flag, zh] = x.split(',')
  return [flag, new RegExp(zh)]
})
export const RE_EMOJI_CN =
  /(?<![\da-z.])(?:CH?N|China)(?!\d*[a-z.])|中[国國]|[广廣贵貴]州|深圳|北京|上海|[广廣山][东東西]|[河湖][北南]|天津|重[庆慶]|[辽遼][宁寧]|吉林|黑[龙龍]江|江[苏蘇西]|浙江|安徽|福建|[海云雲]南|四川|[陕陝]西|甘[肃肅]|青海|[内內]蒙古|西藏|[宁寧]夏|新疆/i
export const RE_EMOJI_INFO =
  /官.?网|官方|产品|平台|勿连|修复|恢复|更新|地址|网站|网址|域名|网域|浏览器|导航|搜|群|裙|聊|频道|电报|飞机|扣|微信|售后|客服|工单|联系|使用|购买|续费|订阅|公告|版本|出现|没网|情况|开通|数量|注|说明|通知|去除|过滤|@|：|(?<![\da-z])(?:tg|telegram|t\.me|qq?|vx?|wx)(?!\d*[a-z]|\d{1,3}(?!\d)|(?:[\da-z-]*\.)?[\da-z-]+\.[a-z])|^[^:]+:(?![\da-f]{0,4}:|\s*\d{1,5}\s*$|\d{1,5}[^\da-z])/i
