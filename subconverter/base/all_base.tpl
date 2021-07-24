{% if request.target == "clash" or request.target == "clashr" %}

port: {{ default(global.clash.http_port, "7890") }}
socks-port: {{ default(global.clash.socks_port, "7891") }}
allow-lan: {{ default(global.clash.allow_lan, "true") }}
mode: Rule
log-level: {{ default(global.clash.log_level, "info") }}
external-controller: :9090
{% if default(request.clash.dns, "") == "1" %}
dns:
  enabled: true
  listen: 1053
{% endif %}
{% if local.clash.new_field_name == "true" %}
proxies: ~
proxy-groups: ~
rules: 
- RULE-SET,Reject,REJECT
- RULE-SET,ADBlock,REJECT
- RULE-SET,USonly,US
- RULE-SET,custom,Proxy

- RULE-SET,Special,DIRECT

- RULE-SET,Netflix,Netflix
- RULE-SET,Spotify,Spotify

- RULE-SET,YouTube,YouTube

- RULE-SET,Bilibili,Domestic
- RULE-SET,iQiyi,Domestic
- RULE-SET,Letv,Domestic
- RULE-SET,Netease Music,Domestic
- RULE-SET,Tencent Video,Domestic
- RULE-SET,Youku,Domestic

- RULE-SET,ABC,GlobalTV
- RULE-SET,Abema TV,GlobalTV
- RULE-SET,Amazon,GlobalTV
- RULE-SET,Apple News,GlobalTV
- RULE-SET,Apple TV,GlobalTV
- RULE-SET,Bahamut,GlobalTV
- RULE-SET,BBC iPlayer,GlobalTV
- RULE-SET,Discovery Plus,GlobalTV
- RULE-SET,Fox+,GlobalTV
- RULE-SET,HBO,GlobalTV
- RULE-SET,Pornhub,GlobalTV

- RULE-SET,Telegram,Telegram
- RULE-SET,Steam,Steam
- RULE-SET,Microsoft,Microsoft

- RULE-SET,PROXY,Proxy
- RULE-SET,Scholar,Proxy

- RULE-SET,Apple,Apple

- RULE-SET,Domestic,Domestic
- RULE-SET,Domestic IPs,Domestic

- RULE-SET,LAN,DIRECT

- GEOIP,CN,Domestic

- MATCH,Domestic

script:
  code: |
    def main(ctx, metadata):
        ruleset_action = {"Reject": "REJECT",
            "custom": "Proxy",
            "ADBlock": "REJECT",
            "USonly": "US",
            "Special": "DIRECT",
            "Netflix": "Netflix",
            "Spotify": "Spotify",
            "YouTube": "YouTube",
            "Disney Plus": "Disney",
            "Bilibili": "AsianTV",
            "iQiyi": "AsianTV",
            "Letv": "AsianTV",
            "Netease Music": "AsianTV",
            "Tencent Video": "AsianTV",
            "Youku": "AsianTV",
            "ABC": "GlobalTV",
            "Abema TV": "GlobalTV",
            "Amazon": "GlobalTV",
            "Apple News": "GlobalTV",
            "Apple TV": "GlobalTV",
            "Bahamut": "GlobalTV",
            "BBC iPlayer": "GlobalTV",
            "Discovery Plus": "GlobalTV",
            "Fox+": "GlobalTV",
            "HBO": "GlobalTV",
            "Pornhub": "GlobalTV",
            "Telegram": "Telegram",
            "Steam": "Steam",
            "Microsoft": "Microsoft",
            "PROXY": "Proxy",
            "Apple": "Apple",
            "Scholar": "Scholar",
            "Domestic": "Domestic",
            "Domestic IPs": "Domestic",
            "LAN": "DIRECT"
          }
        port = int(metadata["dst_port"])
        if metadata["network"] == "UDP":
            if port == 443:
                ctx.log('[Script] matched QUIC traffic use reject')
                return "REJECT"
        port_list = [21, 22, 23, 53, 80, 123, 143, 194, 443, 465, 587, 853, 993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096, 5222, 5228, 5229, 5230, 8080, 8443, 8880, 8888, 8889]
        if port not in port_list:
            ctx.log('[Script] not common port use direct')
            return "DIRECT"
        if metadata["dst_ip"] == "":
            metadata["dst_ip"] = ctx.resolve_ip(metadata["host"])
        for ruleset in ruleset_action:
            if ctx.rule_providers[ruleset].match(metadata):
                return ruleset_action[ruleset]
        if metadata["dst_ip"] == "":
            return "DIRECT"
        code = ctx.geoip(metadata["dst_ip"])
        if code == "CN":
            ctx.log('[Script] Geoip CN')
            return "Domestic"
        ctx.log('[Script] FINAL')
        return "Domestic"

rule-providers:
  Reject:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Reject.yaml'
    path: ./Rules/Reject
    interval: 86400
  ADBlock:
    type: http
    behavior: classical
    url: 'https://raw.githubusercontent.com/tnt2ray/tnt2ray/tnt2ray-patch-1/Clash/ADBlock.yaml'
    path: ./Rules/ADBlock
    interval: 86400
  USonly:
    type: http
    behavior: classical
    url: 'https://raw.githubusercontent.com/tnt2ray/tnt2ray/tnt2ray-patch-1/Clash/US_only.yaml'
    path: ./Rules/USonly
    interval: 86400
  custom:
    type: http
    behavior: classical
    url: 'https://raw.githubusercontent.com/tnt2ray/tnt2ray/tnt2ray-patch-1/Clash/custom.yaml'
    path: ./Rules/custom
    interval: 86400
  Special:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Special.yaml'
    path: ./Rules/Special
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Netflix.yaml'
    path: ./Rules/Media/Netflix
    interval: 86400
  Spotify:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Spotify.yaml'
    path: ./Rules/Media/Spotify
    interval: 86400
  YouTube:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/YouTube.yaml'
    path: ./Rules/Media/YouTube
    interval: 86400
  Bilibili:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Bilibili.yaml'
    path: ./Rules/Media/Bilibili
    interval: 86400
  iQiyi:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/iQiyi.yaml'
    path: ./Rules/Media/iQiyi
    interval: 86400
  Letv:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Letv.yaml'
    path: ./Rules/Media/Letv
    interval: 86400
  Netease Music:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Netease%20Music.yaml'
    path: ./Rules/Media/Netease_Music
    interval: 86400
  Tencent Video:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Tencent%20Video.yaml'
    path: ./Rules/Media/Tencent_Video
    interval: 86400
  Youku:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Youku.yaml'
    path: ./Rules/Media/Youku
    interval: 86400
  ABC:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/ABC.yaml'
    path: ./Rules/Media/ABC
    interval: 86400
  Abema TV:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Abema%20TV.yaml'
    path: ./Rules/Media/Abema_TV
    interval: 86400
  Amazon:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Amazon.yaml'
    path: ./Rules/Media/Amazon
    interval: 86400
  Apple News:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Apple%20News.yaml'
    path: ./Rules/Media/Apple_News
    interval: 86400
  Apple TV:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Apple%20TV.yaml'
    path: ./Rules/Media/Apple_TV
    interval: 86400
  Bahamut:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Bahamut.yaml'
    path: ./Rules/Media/Bahamut
    interval: 86400
  BBC iPlayer:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/BBC%20iPlayer.yaml'
    path: ./Rules/Media/BBC_iPlayer
    interval: 86400
  Discovery Plus:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Discovery%20Plus.yaml'
    path: ./Rules/Media/Discovery_Plus
    interval: 86400
  Disney Plus:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Disney%20Plus.yaml'
    path: ./Rules/Media/Disney_Plus
    interval: 86400
  Fox+:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Fox%2B.yaml'
    path: ./Rules/Media/Fox+
    interval: 86400
  HBO:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/HBO.yaml'
    path: ./Rules/Media/HBO
    interval: 86400
  Pornhub:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Media/Pornhub.yaml'
    path: ./Rules/Media/Pornhub
    interval: 86400
  Telegram:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Telegram.yaml'
    path: ./Rules/Telegram
    interval: 86400
  Steam:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Steam.yaml'
    path: ./Rules/Steam
    interval: 86400
  Microsoft:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Microsoft.yaml'
    path: ./Rules/Microsoft
    interval: 86400
  PROXY:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Proxy.yaml'
    path: ./Rules/Proxy
    interval: 86400
  Domestic:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Domestic.yaml'
    path: ./Rules/Domestic
    interval: 86400
  Apple:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Apple.yaml'
    path: ./Rules/Apple
    interval: 86400
  Scholar:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Scholar.yaml'
    path: ./Rules/Scholar
    interval: 86400
  Domestic IPs:
    type: http
    behavior: ipcidr
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/Domestic%20IPs.yaml'
    path: ./Rules/Domestic_IPs
    interval: 86400
  LAN:
    type: http
    behavior: classical
    url: 'https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Clash/Provider/LAN.yaml'
    path: ./Rules/LAN
    interval: 86400
{% else %}
Proxy: ~
Proxy Group: ~
Rule: ~
{% endif %}

{% endif %}
{% if request.target == "surge" %}

[General]
loglevel = notify
bypass-system = true
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,localhost,*.local,e.crashlytics.com,captive.apple.com,::ffff:0:0:0:0/1,::ffff:128:0:0:0/1
#DNS设置或根据自己网络情况进行相应设置
bypass-tun = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
dns-server = 223.5.5.5, 223.6.6.6, 8.8.8.8, 114.114.114.114, 1.1.1.1
always-real-ip = *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com
hijack-dns = 8.8.8.8:53, 8.8.4.4:53

internet-test-url = http://wifi.vivo.com.cn/generate_204
proxy-test-url = http://cp.cloudflare.com/generate_20
show-error-page-for-reject = true

[URL Rewrite]
# AbeamTV Unlock
^https?:\/\/api\.abema\.io\/v\d\/ip\/check - reject

# Redirect Google Service
^https?:\/\/(www.)?g\.cn https://www.google.com/ 302
^https?:\/\/(www.)?google\.cn https://www.google.com/ 302

# Redirect HTTP to HTTPS
^https?:\/\/(www.)?taobao\.com\/ https://www.taobao.com/ 302
^https?:\/\/(www.)?jd\.com\/ https://www.jd.com/ 302
^https?:\/\/(www.)?mi\.com\/ https://www.mi.com/ 302
^https?:\/\/you\.163\.com\/ https://you.163.com/ 302
^https?:\/\/(www.)?suning\.com/ https://suning.com/ 302
^https?:\/\/(www.)?yhd\.com https://yhd.com/ 302
# Redirect False to True

# >> IGN China to IGN Global
^https?:\/\/(www.)?ign\.xn--fiqs8s\/ http://cn.ign.com/ccpref/us 302

# >> Fake Website Made By Makeding
^https?:\/\/(www.)?abbyychina\.com\/ http://www.abbyy.cn/ 302
^https?:\/\/(www.)?bartender\.cc\/ https://cn.seagullscientific.com 302
^https?:\/\/(www.)?betterzip\.net\/ https://macitbetter.com/ 302
^https?:\/\/(www.)?beyondcompare\.cc\/ https://www.scootersoftware.com/ 302
^https?:\/\/(www.)?bingdianhuanyuan\.cn\/ http://www.faronics.com/zh-hans/ 302
^https?:\/\/(www.)?chemdraw\.com\.cn\/ http://www.cambridgesoft.com/ 302
^https?:\/\/(www.)?codesoftchina\.com\/ https://www.teklynx.com/ 302
^https?:\/\/(www.)?coreldrawchina\.com\/ https://www.coreldraw.com/cn/ 302
^https?:\/\/(www.)?crossoverchina\.com\/ https://www.codeweavers.com/ 302
^https?:\/\/(www.)?easyrecoverychina\.com\/ https://www.ontrack.com/ 302
^https?:\/\/(www.)?ediuschina\.com\/ https://www.grassvalley.com/ 302
^https?:\/\/(www.)?flstudiochina\.com\/ https://www.image-line.com/flstudio/ 302
^https?:\/\/(www.)?formysql\.com\/ https://www.navicat.com.cn 302
^https?:\/\/(www.)?guitarpro\.cc\/ https://www.guitar-pro.com/ 302
^https?:\/\/(www.)?huishenghuiying\.com\.cn\/ https://www.corel.com/cn/ 302
^https?:\/\/(www.)?iconworkshop\.cn\/ https://www.axialis.com/iconworkshop/ 302
^https?:\/\/(www.)?imindmap\.cc\/ https://imindmap.com/zh-cn/ 302
^https?:\/\/(www.)?jihehuaban\.com\.cn\/ https://sketch.io/ 302
^https?:\/\/(www.)?keyshot\.cc\/ https://www.keyshot.com/ 302
^https?:\/\/(www.)?mathtype\.cn\/ http://www.dessci.com/en/products/mathtype/ 302
^https?:\/\/(www.)?mindmanager\.cc\/ https://www.mindjet.com/ 302
^https?:\/\/(www.)?mindmapper\.cc\/ https://mindmapper.com 302
^https?:\/\/(www.)?mycleanmymac\.com\/ https://macpaw.com/cleanmymac 302
^https?:\/\/(www.)?nicelabel\.cc\/ https://www.nicelabel.com/ 302
^https?:\/\/(www.)?ntfsformac\.cc\/ https://www.tuxera.com/products/tuxera-ntfs-for-mac-cn/ 302
^https?:\/\/(www.)?ntfsformac\.cn\/ https://www.paragon-software.com/ufsdhome/zh/ntfs-mac/ 302
^https?:\/\/(www.)?overturechina\.com\/ https://sonicscores.com/overture/ 302
^https?:\/\/(www.)?passwordrecovery\.cn\/ https://cn.elcomsoft.com/aopr.html 302
^https?:\/\/(www.)?pdfexpert\.cc\/ https://pdfexpert.com/zh 302
^https?:\/\/(www.)?ultraiso\.net\/ https://cn.ezbsystems.com/ultraiso/ 302
^https?:\/\/(www.)?vegaschina\.cn\/ https://www.vegas.com/ 302
^https?:\/\/(www.)?xmindchina\.net\/ https://www.xmind.cn/ 302
^https?:\/\/(www.)?xshellcn\.com\/ https://www.netsarang.com/products/xsh_overview.html 302
^https?:\/\/(www.)?yuanchengxiezuo\.com\/ https://www.teamviewer.com/zhcn/ 302
^https?:\/\/(www.)?zbrushcn\.com\/ http://pixologic.com/ 302
^https://aweme-eagle(.*)\.snssdk\.com/aweme/v2/ https://aweme-eagle$1.snssdk.com/aweme/v1/ 302

# JD Protection
^https?:\/\/coupon\.m\.jd\.com\/ https://coupon.m.jd.com/ 302
^https?:\/\/h5\.m\.jd\.com\/ https://h5.m.jd.com/ 302
^https?:\/\/item\.m\.jd\.com\/ https://item.m.jd.com/ 302
^https?:\/\/m\.jd\.com\/ https://m.jd.com/ 302
^https?:\/\/newcz\.m\.jd\.com\/ https://newcz.m.jd.com/ 302
^https?:\/\/p\.m\.jd\.com\/ https://p.m.jd.com/ 302
^https?:\/\/so\.m\.jd\.com\/ https://so.m.jd.com/ 302
^https?:\/\/union\.click\.jd\.com\/jda? http://union.click.jd.com/jda?adblock= header
^https?:\/\/union\.click\.jd\.com\/sem.php? http://union.click.jd.com/sem.php?adblock= header
^https?:\/\/www.jd.com\/ https://www.jd.com/ 302

# TikTok Internation
(?<=(carrier|account|sys|sim)_region=)CN JP 307

# Wiki
# ^https://zh.(m.)?wikipedia.org/zh(-\w*)?(?=/) https://www.wikiwand.com/zh$2 302
# ^https://(\w*).(m.)?wikipedia.org/wiki https://www.wikiwand.com/$1 302

# Resso
(?<=(carrier|account|sys|sim)_region=)cn in 307

# Advertising Block
^https:\/\/(www|cn)\.pornhub\.com\/_xa\/ads.* - reject
^https:\/\/.*\.bebi\.com\/.* - reject
^https:\/\/.*\.club\/floater.* - reject
^https:\/\/.*\.fun\/floater.* - reject
^https:\/\/api-ks\.wtzw\.com\/api\/v(1|2)\/(float-adv|init-adv|reader-adv) - reject
^https:\/\/fb\.fbstatic\.cn\/api\/ape-images\/.*.jpg? - reject
^https:\/\/img\.umetrip\.com\/fs\/advert/ - reject
^https:\/\/js\.dilidd\.com\/top\.php - reject
^https:\/\/mp\.weixin\.qq\.com\/mp\/ad.* - reject
^https:\/\/msg\.umengcloud\.com\/admsg\/ - reject
^https:\/\/weibointl\.api\.weibo\.cn\/portal\.php.*ads&c=ad.* - reject
^https:\/\/www\.dililitv\.com\/wp-author\/tga\/.*ad=.* - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(:\d+)?\/V\d\/splash\/getSplashV\d\.action$ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d):\d+/xygj-config-api\/queryData - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d):\d+\/allOne\.php\?ad_name - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/(adgateway|adv)\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/(outadservice|ting\/preload)\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/.+\.tc\.qq\.com\/.+p201\.1\.mp4\? - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/EcomResourceServer/AdPlayPage/adinfo - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/MobileAdServer\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/[a-z.]+\.tc\.qq\.com\/[\w\W]+=v3004 - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/[a-z.]+\.tc\.qq\.com\/[\w\W]+_p20\d_ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/[a-z.]+\.tc\.qq\.com\/[\w\W]+p20\d\.1\.mp4\? - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/\w+\/\w+\/(sync|newRnSync|mlog) - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/api\/v\d\/app_square\/start_up_with_ad$ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/brand\/search\/v1\.json - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/c\/s\/splashSchedule - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/eapi\/ad\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/g\.real\?aid=text_ad - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/img\/ad\.union\.api\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/music\/common\/upload\/t_splash_info\/ - reject
^https?:\/\/((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/promotion\/(display_cache|display_ad|feed_display|search_ad) - reject
^https?:\/\/(101\.201\.175\.228|182\.92\.251\.113)\/brand\/search\/v1\.json - reject
^https?:\/\/(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}\/(adgateway|adv)\/ - reject
^https?:\/\/(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}\/EcomResourceServer/AdPlayPage/adinfo - reject
^https?:\/\/(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})(\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})){3}\/MobileAdServer\/ - reject
^https?:\/\/(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/ting\/preload\/ - reject
^https?:\/\/(\d{1,3}\.){1,3}\d{1,3}\/view\/dale-online\/dale_ad\/ - reject
^https?:\/\/(\d{1,3}\.){3}\d{1,3}/(variety|vlive\.qqvideo)\.tc\.qq\.com/ - reject
^https?:\/\/(\w\.)?up\.qingdaonews\.(com|cn|net) - reject
^https?:\/\/(a?d|sax)\d.sina.com - reject
^https?:\/\/(api-mifit|api-mifit-\w+)\.huami\.com\/discovery\/mi\/discovery\/\w+_ad\? - reject
^https?:\/\/(api|api-bk\d+)\.tv\.sohu\.com\/agg\/api\/app\/config\/bootstrap - reject
^https?:\/\/(api|atrace)\.chelaile\.net\.cn\/adpub\/ - reject
^https?:\/\/(api|b)\.zhuishushenqi\.com\/advert - reject
^https?:\/\/(api|promo)\.xueqiu\.com\/promotion\/(display_cache|display_ad|feed_display|search_ad) - reject
^https?:\/\/(bdsp-x|dsp-x)\.jd\.com\/adx\/ - reject
^https?:\/\/(e|m).+/((uu|oo).php.+|\d+.x?html\?$) - reject
^https?:\/\/(gw|heic)\.alicdn\.com\/\w{2}s\/.+\.jpg_(9\d{2}|\d{4}) - reject
^https?:\/\/(gw|heic)\.alicdn\.com\/imgextra\/.+\d{4}-\d{4}\.jpg_(9\d{2}|\d{4}) - reject
^https?:\/\/(iyes|(api|hd)\.mobile)\.youku\.com\/(adv|common\/v3\/hudong\/new) - reject
^https?:\/\/(s3plus|flowplus)\.meituan\.net\/v\d\/\w+\/linglong\/\w+\.(gif|jpg|mp4) - reject
^https?:\/\/.+/videos/other/.+ - reject
^https?:\/\/.+?/V\d\/splash\/getSplashV\d\.action - reject
^https?:\/\/.+?\.(musical|snssdk)\.(com|ly)\/(api|motor)\/ad\/ - reject
^https?:\/\/.+?\.(musical|snssdk|tiktokv)\.(com|ly)\/(api|motor)\/ad\/ - reject
^https?:\/\/.+?\.(snssdk|amemv)\.com\/api\/ad\/ - reject
^https?:\/\/.+?\.127\.net\/ad - reject
^https?:\/\/.+?\.58cdn\.com\.cn\/brandads\/ - reject
^https?:\/\/.+?\.atm\.youku\.com - reject
^https?:\/\/.+?\.beacon\.qq\.com - reject
^https?:\/\/.+?\.iydsj\.com\/api\/.+?\/ad - reject
^https?:\/\/.+?\.l\.qq\.com - reject
^https?:\/\/.+?\.mp4\?ccode=0902 - reject
^https?:\/\/.+?\.mp4\?sid= - reject
^https?:\/\/.+?\.pstatp\.com\/img\/ad - reject
^https?:\/\/.+?\.snssdk\.com\/motor\/operation\/activity\/display\/config\/V2\/ - reject
^https?:\/\/.+?\/(mixer|track2)\? - reject
^https?:\/\/.+?\/allOne\.php\?ad_name - reject
^https?:\/\/.+?\/api\/app\/member\/ver2\/user\/login\/ - reject
^https?:\/\/.+?\/api\/v\d\/adRealTime - reject
^https?:\/\/.+?\/cdn-adn\/ - reject
^https?:\/\/.+?\/client?functionId=lauch\/lauchConfig&appName=paidaojia - reject
^https?:\/\/.+?\/eapi\/(ad|log)\/ - reject
^https?:\/\/.+?\/eapi\/[ad|event]\/ - reject
^https?:\/\/.+?\/eapi\/ad\/ - reject
^https?:\/\/.+?\/hls.cache.p4p\/ - reject
^https?:\/\/.+?\/img\/ad\.union\.api\/ - reject
^https?:\/\/.+?\/img\/web\.business\.image\/ - reject
^https?:\/\/.+?\/letv-gug\/ - reject
^https?:\/\/.+?\/music\/common\/upload\/t_splash_info - reject
^https?:\/\/.+?\/portal\.php\?a=get_ads - reject
^https?:\/\/.+?\/portal\.php\?a=get_coopen_ads - reject
^https?:\/\/.+?\/portal\.php\?c=duiba - reject
^https?:\/\/.+?\/resource\/m\/promo\/adsense - reject
^https?:\/\/.+?\/resource\/m\/sys\/app\/adpos - reject
^https?:\/\/.+?\/tips\/fcgi-bin\/fcg_get_advert - reject
^https?:\/\/.+?\/v1\/iflyad\/ - reject
^https?:\/\/.+?\/v2\/app_ads\/ - reject
^https?:\/\/.+?\/v\d\/iflyad\/ - reject
^https?:\/\/.+?\/variety.tc.qq.com\/ - reject
^https?:\/\/.+?\/videos\/KnifeHit_4\/gear3\/ - reject
^https?:\/\/.+?\/vips-mobile\/router\.do\?api_key= - reject
^https?:\/\/.+?\/weico4ad\/ad\/ - reject
^https?:\/\/.+?allOne\.php\?ad_name=main_splash_ios - reject
^https?:\/\/.+?ccode=0902 - reject
^https?:\/\/.+?resource=article\/recommend\&accessToken= - reject
^https?:\/\/101\.201\.175\.228\/ads\/display - reject
^https?:\/\/113\.200\.76\.*?:16420\/sxtd\.bike2\.01\/getkey\.do - reject
^https?:\/\/118\.178\.214\.118\/yyting\/advertclient\/ClientAdvertList\.action - reject
^https?:\/\/119\.18\.193\.135\/(adgateway|adv)\/ - reject
^https?:\/\/122\.14\.246\.33\/MobileAdServer\/ - reject
^https?:\/\/123\.59\.30\.10\/adv\/advInfos - reject
^https?:\/\/123\.59\.31\.1\/(adgateway|adv)\/ - reject
^https?:\/\/182\.92\.244\.70\/d\/json\/ - reject
^https?:\/\/192\.133.+?\.mp4$ - reject
^https?:\/\/203\.205\.255\.16\/retrieval\/getAd - reject
^https?:\/\/211\.98\.71\.(195|196|226):8080\/ - reject
^https?:\/\/3gimg\.qq\.com\/tencentMapTouch\/app\/activity\/ - reject
^https?:\/\/3gimg\.qq\.com\/tencentMapTouch\/splash\/ - reject
^https?:\/\/47\.97\.20\.12\/ad\/ - reject
^https?:\/\/4gimg\.map\.qq\.com\/mwaSplash\/ - reject
^https?:\/\/789\.kakamobi\.cn\/.+?adver - reject
^https?:\/\/7n\.bczcdn\.com\/launchad\/ - reject
^https?:\/\/9377\w{2}\.com - reject
^https?:\/\/[\s\S]*\.baidu\.com/.*?ad[xs]\.php - reject
^https?:\/\/[\s\S]*\.snssdk\.com\/api\/ad\/ - reject
^https?:\/\/[\s\S]*\/eapi\/ad\/ - reject
^https?:\/\/[\s\S]*\/music\/photo_new\/T017R - reject
^https?:\/\/[\s\S]*\/ting\/[a-z]*\/ts-\d+ - reject
^https?:\/\/[\s\S]*\/website\/.*?\.jpg - reject
^https?:\/\/[\s\S]*\/youku\/.*?\.mp4 - reject
^https?:\/\/[\s\s]*baidu\.com/.*ad[xs]\.php - reject
^https?:\/\/[\w-]+\.(amemv|musical|snssdk|tiktokv)\.(com|ly)\/(api|motor)\/ad\/ - reject
^https?:\/\/[\w-]+\.snssdk\.com\/.+_ad\/ - reject
^https?:\/\/[^(apple|10010)]+\.(com|cn)\/(a|A)d(s|v)?(/|\.js) - reject
^https?:\/\/[^bbs].tianya\.cn - reject
^https?:\/\/\w+?\.ximalaya\.com\/api\/v\d\/adRealTime - reject
^https?:\/\/\w+\.beacon\.qq\.com - reject
^https?:\/\/\w+\.cloudfront\.net\/banner - reject
^https?:\/\/\w+\.gdt\.qq\.com - reject
^https?:\/\/\w+\.jstucdn\.com\/(g3\/|js\/ad) - reject
^https?:\/\/\w+\.kakamobi\.cn\/api\/open\/v\d\/advert-sdk\/ - reject
^https?:\/\/\w+\.kingsoft-office-service\.com\/ad - reject
^https?:\/\/\w+\.l\.qq\.com - reject
^https?:\/\/\w.?up\.qingdaonews\.com - reject
^https?:\/\/\w{6}.com1.z0.glb.clouddn.com - reject
^https?:\/\/\w{6}\.com1\.z0\.glb\.clouddn\.com - reject
^https?:\/\/\w{8}\.logic\.cpm\.cm\.kankan\.com - reject
^https?:\/\/a0b\w{2}\.com - reject
^https?:\/\/a\.apicloud\.com\/start_page\/ - reject
^https?:\/\/a\.applovin\.com\/.+?\/ad - reject
^https?:\/\/a\.applovin\.com\/3\.0\/ad - reject
^https?:\/\/a\.qiumibao\.com\/activities\/config\.php - reject
^https?:\/\/aarkissltrial\.secure2\.footprint\.net\/v1\/ads - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.alibaba\.advertisementservice\.getadv - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.alimusic\.common\.mobileservice\.startinit\/ - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.film\.mtopadvertiseapi\.queryadvertise\/ - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.o2o\.ad\.gateway\.get\/ - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.taobao\.idle\.home\.welcome\/ - reject
^https?:\/\/acs\.m\.taobao\.com\/gw\/mtop\.trip\.activity\.querytmsresources\/ - reject
^https?:\/\/act\.vip\.iqiyi\.com\/interact\/api\/show\.do - reject
^https?:\/\/act\.vip\.iqiyi\.com\/interact\/api\/v2\/show - reject
^https?:\/\/activity2\.api\.ofo\.com\/ofo\/Api\/v2\/ads - reject
^https?:\/\/ad\.api\.3g\.youku\.com - reject
^https?:\/\/ad\.api\.moji\.com\/ad\/log\/stat - reject
^https?:\/\/ad\d\.sina\.com - reject
^https?:\/\/ad\d\.sina\.com.cn - reject
^https?:\/\/adm\.10jqka\.com\.cn\/img\/ad\/.*?(1\d{2}|\d{4})\.jpg - reject
^https?:\/\/adm\.10jqka\.com\.cn\/interface\/getads\.php - reject
^https?:\/\/adpai\.thepaper\.cn\/.+?&ad= - reject
^https?:\/\/adproxy\.autohome\.com\.cn\/AdvertiseService\/ - reject
^https?:\/\/adse.+?\.com\/[a-z]{4}\/loading\?appid= - reject
^https?:\/\/adse\.ximalaya\.com\/ting\/feed\?appid= - reject
^https?:\/\/adse\.ximalaya\.com\/ting\/loading\?appid= - reject
^https?:\/\/adse\.ximalaya\.com\/ting\?appid= - reject
^https?:\/\/aes\.acfun\.cn\/s\?adzones - reject
^https?:\/\/afd\.baidu\.com\/afd\/entry - reject
^https?:\/\/agent-count\.pconline\.com\.cn\/counter\/adAnalyse\/ - reject
^https?:\/\/agn\.aty\.sohu\.com\/m? - reject
^https?:\/\/alogs\.umeng\.co - reject
^https?:\/\/als\.baidu\.com\/clog\/clog - reject
^https?:\/\/api-163\.biliapi\.net\/cover - reject
^https?:\/\/api-mifit\.huami\.com\/(discovery\/mi\/discovery\/(homepage|sleep|sport(_(summary|training))?|step_detail|training_video)_ad|v1\/app\/startpages\.json)\? - reject
^https?:\/\/api-new\.app\.acfun\.cn\/rest\/app\/flash\/screen\/ - reject
^https?:\/\/api-release\.wuta-cam\.com\/ad_tree - reject
^https?:\/\/api2\.helper\.qq\.com\/game\/buttons - reject
^https?:\/\/api\.(pinduoduo|yangkeduo)\.com\/api\/cappuccino\/splash - reject
^https?:\/\/api\.21jingji\.com\/ad\/ - reject
^https?:\/\/api\.app\.vhall\.com\/v5\/000\/webinar\/launch - reject
^https?:\/\/api\.applovefrom\.com\/api\/v\d\/splash\/ - reject
^https?:\/\/api\.appsdk\.soku\.com\/bg\/r - reject
^https?:\/\/api\.bjxkhc\.com\/index\.php\/app\/ios\/ads\/ - reject
^https?:\/\/api\.caijingmobile\.com\/(ad|advert)\/ - reject
^https?:\/\/api\.catch\.gift\/api\/v\d\/pagead\/ - reject
^https?:\/\/api\.cdmcaac\.com\/ad\/ - reject
^https?:\/\/api\.chelaile\.net\.cn\/adpub\/ - reject
^https?:\/\/api\.chelaile\.net\.cn\/goocity\/advert\/ - reject
^https?:\/\/api\.club\.lenovo\.cn\/common\/open_ad - reject
^https?:\/\/api\.daydaycook\.com\.cn\/daydaycook\/server\/ad\/ - reject
^https?:\/\/api\.douban\.com\/v2\/app_ads\/common_ads - reject
^https?:\/\/api\.douban\.com\/v2\/app_ads\/splash - reject
^https?:\/\/api\.eshimin\.com\/api\/core\/version - reject
^https?:\/\/api\.feng\.com[\s\S]*?Claunch_screen - reject
^https?:\/\/api\.feng\.com\/v\d\/advertisement\/.*Claunch - reject
^https?:\/\/api\.fengshows\.com\/api\/launchAD - reject
^https?:\/\/api\.futunn\.com\/v\d\/ad\/ - reject
^https?:\/\/api\.gaoqingdianshi\.com\/api\/v2\/ad - reject
^https?:\/\/api\.gotokeep\.com\/ads - reject
^https?:\/\/api\.hanju\.koudaibaobao\.com\/api\/carp\/kp\? - reject
^https?:\/\/api\.haohaozhu\.cn\/index\.php\/home\/AppInit\/getStartPhoto - reject
^https?:\/\/api\.huomao\.com\/channels\/loginAd - reject
^https?:\/\/api\.intsig\.net\/user\/cs\/operating\/app\/get_startpic\/ - reject
^https?:\/\/api\.ishansong\.com\/app\/check\/v\d+\/check - reject
^https?:\/\/api\.izuiyou\.com\/ad\/ - reject
^https?:\/\/api\.jr\.mi\.com\/jr\/api\/playScreen - reject
^https?:\/\/api\.jr\.mi\.com\/v\d\/adv\/ - reject
^https?:\/\/api\.jxedt\.com\/ad\/ - reject
^https?:\/\/api\.jxedt\.com\/jump\/EMiCcDNp - reject
^https?:\/\/api\.k\.sohu\.com\/api\/channel\/ad\/ - reject
^https?:\/\/api\.k\.sohu\.com\/api\/news\/adsense - reject
^https?:\/\/api\.kkmh\.com\/v\d+\/(ad|advertisement)\/ - reject
^https?:\/\/api\.laifeng\.com\/v\d\/start\/ads - reject
^https?:\/\/api\.laosiji\.com\/user\/startpage\/ - reject
^https?:\/\/api\.m\.jd\.com\/openUpgrade - reject
^https?:\/\/api\.m\.mi\.com\/v\d\/app\/start - reject
^https?:\/\/api\.mddcloud\.com\.cn\/api\/ad\/getClassAd\.action - reject
^https?:\/\/api\.mddcloud\.com\.cn\/api\/advert\/getHomepage\.action - reject
^https?:\/\/api\.meipian\.me.+?advert - reject
^https?:\/\/api\.mgzf\.com\/renter-operation\/home\/startHomePage - reject
^https?:\/\/api\.mobile\.youku\.com\/layout\/search\/hot\/word - reject
^https?:\/\/api\.newad\.ifeng\.com\/ClientAdversApi1508\?adids= - reject
^https?:\/\/api\.psy-1\.com\/cosleep\/startup - reject
^https?:\/\/api\.qbb6\.com\/ad\/ - reject
^https?:\/\/api\.qiuduoduo\.cn\/guideimage - reject
^https?:\/\/api\.rr\.tv\/.*?(getAll|Version) - reject
^https?:\/\/api\.rr\.tv\/ad\/ - reject
^https?:\/\/api\.share\.mob\.com\/snsconf - reject
^https?:\/\/api\.smzdm\.com\/v2\/util\/banner - reject
^https?:\/\/api\.tv\.sohu\.com\/agg\/api\/app\/config\/bootstrap - reject
^https?:\/\/api\.videozhishi\.com\/api\/getAdvertising - reject
^https?:\/\/api\.vistopia\.com\.cn\/api\/v\d\/home\/advertisement - reject
^https?:\/\/api\.vuevideo\.net\/api\/v\d\/ad\/ - reject
^https?:\/\/api\.waitwaitpay\.com\/\/api\/splash - reject
^https?:\/\/api\.wallstreetcn\.com\/apiv\d\/advertising\/ - reject
^https?:\/\/api\.weibo\.cn\/2\/statuses\/extend\?gsid= - reject
^https?:\/\/api\.xiachufang\.com\/v\d\/ad/ - reject
^https?:\/\/api\.xueqiu\.com\/ads\/display - reject
^https?:\/\/api\.xueqiu\.com\/brand\/search\/v1\.json - reject
^https?:\/\/api\.yangkeduo\.com\/api\/cappuccino\/splash - reject
^https?:\/\/api\.ycapp\.yiche\.com\/appnews\/getadlist - reject
^https?:\/\/api\.ycapp\.yiche\.com\/yicheapp\/getadlist - reject
^https?:\/\/api\.ycapp\.yiche\.com\/yicheapp\/getappads\/ - reject
^https?:\/\/api\.yizhibo\.com\/common\/api\/api_pz$ - reject
^https?:\/\/api\.zhuishushenqi\.com\/notification\/shelfMessage - reject
^https?:\/\/api\.zhuishushenqi\.com\/recommend - reject
^https?:\/\/api\.zhuishushenqi\.com\/splashes\/ios - reject
^https?:\/\/api\.zhuishushenqi\.com\/user\/bookshelf-updated - reject
^https?:\/\/api\d?\.musical\.ly\/api\/ad\/ - reject
^https?:\/\/api\d?\.tiktokv\.com\/api\/ad\/ - reject
^https?:\/\/api\d\.futunn\.com\/ad\/ - reject
^https?:\/\/apimobile\.meituan\.com\/appupdate\/mach\/checkUpdate? - reject
^https?:\/\/app-api\.jinse\.com\/v\d\/ad\/ - reject
^https?:\/\/app-api\.niu\.com\/v\d\/advertisement\/ - reject
^https?:\/\/app2\.autoimg\.cn\/appdfs\/ - reject
^https?:\/\/app3\.qdaily\.com\/app3\/boot_advertisements\.json - reject
^https?:\/\/app\.10086\.cn\/biz-orange\/DN\/(findSale|homeSale)\/getsaleAdver - reject
^https?:\/\/app\.58\.com\/api\/home\/(advertising|appadv)\/ - reject
^https?:\/\/app\.58\.com\/api\/home\/invite\/popupAdv - reject
^https?:\/\/app\.58\.com\/api\/log\/ - reject
^https?:\/\/app\.api\.ke\.com\/config\/config\/bootpage - reject
^https?:\/\/app\.ddpai\.com\/d\/api\/v\d\/config\/get\/bootscreen - reject
^https?:\/\/app\.mixcapp\.com\/mixc\/api\/v\d\/ad - reject
^https?:\/\/app\.poizon\.com\/api\/v\d\/app\/advertisement\/ - reject
^https?:\/\/app\.relxtech\.com\/dianziyan-api\/api\/screen\/advert\/random - reject
^https?:\/\/app\.variflight\.com\/ad\/ - reject
^https?:\/\/app\.variflight\.com\/v\d\/advert\/ - reject
^https?:\/\/app\.veryzhun\.com\/ad\/admob - reject
^https?:\/\/app\.wy\.guahao\.com\/json\/white\/dayquestion\/getpopad - reject
^https?:\/\/app\.xinpianchang\.com\/open_screen\? - reject
^https?:\/\/app\.yinxiang\.com\/ads\/ - reject
^https?:\/\/app\.yinxiang\.com\/ads\/getAdsInfo - reject
^https?:\/\/app\.zhuanzhuan\.com\/zzx\/transfer\/getConfigInfo$ - reject
^https?:\/\/appapi\.huazhu\.com:\d{4}\/client\/app\/getAppStartPage\/ - reject
^https?:\/\/appconf\.mail\.163\.com\/mmad\/ - reject
^https?:\/\/apprn\.pizzahut\.com\.cn\/updateCheck\? - reject
^https?:\/\/appv6\.55haitao\.com\/IflyAd\/getAd - reject
^https?:\/\/asp\.cntv\.myalicdn\.com\/.+?\?maxbr=850 - reject
^https?:\/\/ast\.api\.moji\.com\/assist\/ad\/moji\/stat - reject
^https?:\/\/atrace\.chelaile\.net\.cn\/adpub\/ - reject
^https?:\/\/atrace\.chelaile\.net\.cn\/exhibit\?&adv_image - reject
^https?:\/\/aweme\.snssdk\.com\/aweme\/v1\/aweme\/stats\/ - reject
^https?:\/\/aweme\.snssdk\.com\/aweme\/v1\/device\/update\/ - reject
^https?:\/\/aweme\.snssdk\.com\/aweme\/v1\/screen\/ad\/ - reject
^https?:\/\/aweme\.snssdk\.com\/service\/1\/app_logout\/ - reject
^https?:\/\/aweme\.snssdk\.com\/service\/2\/app_log - reject
^https?:\/\/b-api\.ins\.miaopai\.com\/\d\/ad/ - reject
^https?:\/\/baichuan\.baidu\.com\/rs\/adpmobile\/launch - reject
^https?:\/\/bank\.wo\.cn\/v9\/getstartpage - reject
^https?:\/\/bbs\.airav\.cc\/data\/.+?\.jpg - reject
^https?:\/\/bdsp-x\.jd\.com\/adx\/ - reject
^https?:\/\/bj\.bcebos\.com\/fc-feed\/0\/pic\/ - reject
^https?:\/\/bla\.gtimg\.com\/qqlive\/\d{6}.+?\.png - reject
^https?:\/\/book\.img\.ireader\.com\/group6\/M00 - reject
^https?:\/\/btrace\.qq\.com - reject
^https?:\/\/business-cdn\.shouji\.sogou\.com\/wapdl\/hole\/.+?\.jpg - reject
^https?:\/\/business\.msstatic\.com\/advertiser\/ - reject
^https?:\/\/c1\.ifengimg\.com\/.+?_w1080_h1410\.jpg - reject
^https?:\/\/c\.m\.163\.com\/nc\/gl\/ - reject
^https?:\/\/c\.minisplat\.cn - reject
^https?:\/\/c\.tieba\.baidu\.com\/\w+\/\w+\/(sync|newRnSync|newlog|mlog) - reject
^https?:\/\/c\.tieba\.baidu\.com\/c\/f\/forum\/getAdInfo - reject
^https?:\/\/c\.tieba\.baidu\.com\/c\/p\/img\?src= - reject
^https?:\/\/c\.tieba\.baidu\.com\/c\/s\/logtogether\?cmd= - reject
^https?:\/\/c\.tieba\.baidu\.com\/c\/s\/splashSchedule - reject
^https?:\/\/cache\.changjingyi\.cn - reject
^https?:\/\/cache\.gclick\.cn - reject
^https?:\/\/cap\.caocaokeji\.cn\/advert-bss\/ - reject
^https?:\/\/capi.mwee.cn/app-api/V\d+/app/(ad|getstartad) - reject
^https?:\/\/capi\.douyucdn\.cn\/api\/ios_app\/check_update - reject
^https?:\/\/capi\.douyucdn\.cn\/api\/v1\/getStartSend?client_sys=ios - reject
^https?:\/\/capi\.douyucdn\.cn\/lapi\/sign\/app(api)?\/getinfo\?client_sys=ios - reject
^https?:\/\/capis(-?\w*)?\.didapinche\.com\/ad\/boot\? - reject
^https?:\/\/capis(-?\w*)?\.didapinche\.com\/ad\/event? - reject
^https?:\/\/capis(-?\w*)?\.didapinche\.com\/ad\/ride\/detail\? - reject
^https?:\/\/capis(-?\w*)?\.didapinche\.com\/publish\/api\/upgrade - reject
^https?:\/\/ccsp-egmas\.sf-express\.com\/cx-app-base\/base\/app\/ad\/ - reject
^https?:\/\/ccsp-egmas\.sf-express\.com\/cx-app-base\/base\/app\/ad\/queryAdImages - reject
^https?:\/\/ccsp-egmas\.sf-express\.com\/cx-app-base\/base\/app\/appVersion\/detectionUpgrade - reject
^https?:\/\/cdn-1rtb\.caiyunapp\.com/creative/.*$ - reject
^https?:\/\/cdn2\.moji002\.com\/webpush\/ad2\/ - reject
^https?:\/\/cdn\.api\.fotoable\.com\/Advertise\/ - reject
^https?:\/\/cdn\.dianshihome\.com\/static\/ad\/ - reject
^https?:\/\/cdn\.kuaidi100\.com\/images\/open\/appads - reject
^https?:\/\/cdn\.moji\.com\/(adoss|adlink)\/ - reject
^https?:\/\/cdn\.moji\.com\/adlink\/avatarcard - reject
^https?:\/\/cdn\.moji\.com\/adlink\/common - reject
^https?:\/\/cdn\.moji\.com\/adlink\/splash\/ - reject
^https?:\/\/cdn\.moji\.com\/advert\/ - reject
^https?:\/\/cdn\.tiku\.zhan\.com\/banner - reject
^https?:\/\/cdnfile1\.msstatic\.com\/cdnfile\/appad\/ - reject
^https?:\/\/cdnfile1\.msstatic\.com\/cdnfile\/appad\/resource - reject
^https?:\/\/channel\.beitaichufang\.com\/channel\/api\/v1\/promote\/ios\/start\/page - reject
^https?:\/\/cheyouapi\.ycapp\.yiche\.com\/appforum\/getusermessagecount - reject
^https?:\/\/classbox2\.kechenggezi\.com\/api\/v1\/sponge\/pull\?request_time= - reject
^https?:\/\/client\.mail\.163\.com\/apptrack\/confinfo\/searchMultiAds - reject
^https?:\/\/client\.qunar\.com\/pitcher-proxy\?qrt=p_splashAd - reject
^https?:\/\/clientaccess\.10086\.cn\/biz-orange\/DN\/init\/startInit - reject
^https?:\/\/cloud\.189\.cn\/include\/splash\/ - reject
^https?:\/\/cms\.daydaycook\.com\.cn\/api\/cms\/advertisement\/ - reject
^https?:\/\/cmsapi\.wifi8\.com\/v\d\/(emptyAd|adNew)\/ - reject
^https?:\/\/cmsfile\.wifi8\.com\/uploads\/png\/ - reject
^https?:\/\/cntv\.hls\.cdn\.myqcloud\.com\/.+?\?maxbr=850 - reject
^https?:\/\/connect\.facebook\.net\/en_US\/fbadnw\.js - reject
^https?:\/\/consumer\.fcbox\.com\/v1\/ad\/OpeningAdInfo\/ - reject
^https?:\/\/consumer\.fcbox\.com\/v\d\/ad\/ - reject
^https?:\/\/counter\.ksosoft\.com\/ad\.php - reject
^https?:\/\/cover.baidu.com\/cover\/page\/dspSwitchAds\/ - reject
^https?:\/\/creatives\.ftimg\.net\/ads - reject
^https?:\/\/creditcard\.ecitic\.com\/citiccard\/wtk\/piwik\/piwik\.php - reject
^https?:\/\/creditcardapp\.bankcomm\.com\/mapp\/common\/getPopAds\.do$ - reject
^https?:\/\/creditcardapp\.bankcomm\.com\/mapp\/common\/queryGuidePageAds\.do - reject
^https?:\/\/ct\.xiaojukeji\.com\/agent\/v3\/feeds - reject
^https?:\/\/ctrl\.(playcvn|zmzapi)\.(com|net)\/app\/(ads|init) - reject
^https?:\/\/ctrl\.zmzapi\.net\/app\/ads - reject
^https?:\/\/ctrl\.zmzapi\.net\/app\/init - reject
^https?:\/\/d\.1qianbao\.com\/youqian\/ads\/ - reject
^https?:\/\/d\.zhangle\.com\/pic\/cft\/interaction\/\d{13}-1242-2248\.jpg - reject
^https?:\/\/d\d.sinaimg.cn - reject
^https?:\/\/daoyu\.sdo\.com\/api\/userCommon\/getAppStartAd - reject
^https?:\/\/dapis\.mting\.info\/yyting\/advertclient\/ClientAdvertList\.action - reject
^https?:\/\/dd\.iask\.cn\/ddd\/adAudit - reject
^https?:\/\/ddrk\.me\/image\/logo_footer\.png$ - reject
^https?:\/\/ddrk\.me\/wp-content\/plugins\/advanced-floating-content-lite\/public\/images\/close\.png - reject
^https?:\/\/dict-mobile\.iciba\.com\/interface\/index\.php\?.+?(c=ad|collectFeedsAdShowCount|KSFeedsAdCardViewController) - reject
^https?:\/\/dili\.bdatu\.com\/jiekou\/ad\/ - reject
^https?:\/\/dimg04\.c-ctrip\.com\/images\/\w+(_\d{4}){2} - reject
^https?:\/\/discuz\.gtimg\.cn\/cloud\/scripts\/discuz_tips\.js - reject
^https?:\/\/dl.app.gtja.com/.+\d+.jpg$ - reject
^https?:\/\/dl\.app.gtja\.com\/.+?\d+\.jpg$ - reject
^https?:\/\/dl\.app\.gtja\.com\/dzswem\/kvController\/.+?\.jpg$ - reject
^https?:\/\/dl\.app\.gtja\.com\/operation\/config\/startupConfig\.json - reject
^https?:\/\/douyucdn\.cn\/.+?\/appapi\/getinfo - reject
^https?:\/\/dsa-mfp\.fengshows\.cn\/mfp\/mfpMultipleDelivery\.do\?.+?adunitid - reject
^https?:\/\/dsp-impr2\.youdao\.com\/adload - reject
^https?:\/\/dsp\.toutiao\.com\/api\/xunfei\/ads\/ - reject
^https?:\/\/dssp\.stnts\.com - reject
^https?:\/\/du\.hupucdn\.com\/\w+h\d{4} - reject
^https?:\/\/dxy\.com\/app\/i\/ask\/biz\/feed\/launch - reject
^https?:\/\/e\.dangdang\.com\/.+?getDeviceStartPage - reject
^https?:\/\/e\.dangdang\.com\/media\/api.+?\?action=getDeviceStartPage - reject
^https?:\/\/easyreadfs\.nosdn\.127\.net\/ad-material\/ - reject
^https?:\/\/edit\.sinaapp\.com\/ua\?t=adv - reject
^https?:\/\/elemecdn\.com\/.+?\/sitemap - reject
^https?:\/\/emdcadvertise\.eastmoney\.com\/infoService - reject
^https?:\/\/erebor\.douban\.com\/count\/\?ad= - reject
^https?:\/\/exp\.3g\.ifeng\.com\/coverAdversApi\?gv=\. - reject
^https?:\/\/fcvbjbcebos\.baidu\.com\/.+?\.mp4 - reject
^https?:\/\/fdfs\.xmcdn\.com\/group21\/M03\/E7\/3F\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group21\/M0A\/95\/3B\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group22\/M00\/92\/FF\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group22\/M05\/66\/67\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group22\/M07\/76\/54\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group23\/M01\/63\/F1\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group23\/M04\/E5\/F6\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group23\/M07\/81\/F6\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group23\/M0A\/75\/AA\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group24\/M03\/E6\/09\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group24\/M07\/C4\/3D\/ - reject
^https?:\/\/fdfs\.xmcdn\.com\/group25\/M05\/92\/D1\/ - reject
^https?:\/\/fds\.api\.moji\.com\/card\/recommend - reject
^https?:\/\/fengplus\.feng\.com\/index\.php\?r=api\/slide\/.+?Ads - reject
^https?:\/\/fm\.fenqile\.com\/routev2\/other\/getfloatAd\.json - reject
^https?:\/\/fm\.fenqile\.com\/routev2\/other\/startImg\.json - reject
^https?:\/\/fmapp\.chinafamilymart\.com\.cn\/api\/app\/biz\/base\/appversion\/latest - reject
^https?:\/\/foodie-api\.yiruikecorp\.com\/v\d\/(banner|notice)\/overview - reject
^https?:\/\/free\.sinaimg\.cn\/u1\.img\.mobile\.sina\.cn - reject
^https?:\/\/frontier\.snssdk\.com\/ - reject
^https?:\/\/fuss10\.elemecdn\.com\/.+?\.mp4 - reject
^https?:\/\/fuss10\.elemecdn\.com\/.+?\/w\/640\/h\/\d{3,4} - reject
^https?:\/\/g1\.163\.com\/madfeedback - reject
^https?:\/\/g\.cdn\.pengpengla\.com\/starfantuan\/boot-screen-info\/ - reject
^https?:\/\/g\.tbcdn\.cn\/mtb\/ - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/.+?\/(interfaceAdMonitor|interfaceAd)\/ - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/.+?\/(search|interfaceAdMonitor|status|hupuBbsPm)/(hotkey|init|hupuBbsPm)\. - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/.+?\/interfaceAdMonitor\/ - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/.+?\/status\/init - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/\d\/(?:\d\.){2}\d\/status\/init - reject
^https?:\/\/games\.mobileapi\.hupu\.com\/interfaceAdMonitor - reject
^https?:\/\/gateway\.shouqiev\.com(:8443)?\/fsda\/app\/bootImage\.json - reject
^https?:\/\/gateway\.shouqiev\.com\/fsda\/app\/bootImage\.json - reject
^https?:\/\/gfp\.veta\.naver\.com\/adcall\? - reject
^https?:\/\/gg\w+?\.cmvideo\.cn\/v\d\/iflyad\/ - reject
^https?:\/\/ggic\d?\.cmvideo\.cn\/ad\/ - reject
^https?:\/\/ggv\.cmvideo\.cn\/v1\/iflyad\/ - reject
^https?:\/\/ggx\.cmvideo\.cn\/request\/ - reject
^https?:\/\/gss0\.bdstatic\.com\/.+?\/static\/wiseindex\/img\/bd_red_packet\.png - reject
^https?:\/\/gw-passenger\.01zhuanche\.com\/gw-passenger\/car-rest\/webservice\/passenger\/recommendADs - reject
^https?:\/\/gw-passenger\.01zhuanche\.com\/gw-passenger\/zhuanche-passenger-token\/leachtoken\/webservice\/homepage\/queryADs - reject
^https?:\/\/gw-passenger\.01zhuanche\.com\/gw-passenger\/zhuanche-passengerController\/notk\/passenger\/recommendADs - reject
^https?:\/\/gw\.aihuishou\.com\/app-portal\/home\/getadvertisement - reject
^https?:\/\/gw\.csdn\.net\/cms-app\/v\d+\/home_page\/open_advertisement - reject
^https?:\/\/h\w{2}\.hxsame\.hexun\.com - reject
^https?:\/\/haojia\.m\.smzdm\.com\/detail_modul\/banner - reject
^https?:\/\/heic\.alicdn\.com\/tps\/i4\/.+?\.jpg_1200x1200q90\.jpg_\.heic$ - reject
^https?:\/\/hk\.app\.joox\.com\/billsrv\/clientBatchAdReport - reject
^https?:\/\/hk\.app\.joox\.com\/retrieval\/getAd - reject
^https?:\/\/home\.mi\.com\/cgi-op\/api\/v\d\/recommendation\/banner - reject
^https?:\/\/hui\.sohu\.com\/predownload2\/? - reject
^https?:\/\/huichuan\.sm\.cn\/jsad - reject
^https?:\/\/i1\.hoopchina\.com\.cn\/blogfile\/.+?_\d{3}x\d{4} - reject
^https?:\/\/i\.ys7\.com\/api\/ads - reject
^https?:\/\/i\d\.hoopchina\.com\.cn/blogfile\\/\/d+\\/\/d+\/BbsImg\.(?<=(big.(png|jpg)))$ - reject
^https?:\/\/iad.*?mat\.music\.12[67]\.net/\w+\.(jpg|mp4) - reject
^https?:\/\/iad.*mat\.[a-z]*\.12[67]\.net/\w+\.(jpg|mp4)$ - reject
^https?:\/\/iadmusicmat\.music.126.net\/.*?jpg$ - reject
^https?:\/\/iapi\.bishijie\.com\/actopen\/advertising\/ - reject
^https?:\/\/ib-soft\.net\/icleaner\/txt\/ad_priority\.txt$ - reject
^https?:\/\/icc\.one\/iFreeTime\/xid32uxaoecnfv2\/ - reject
^https?:\/\/iface2\.iqiyi\.com\/fusion\/3\.0\/fusion_switch - reject
^https?:\/\/iface\.iqiyi\.com\/api\/getNewAdInfo - reject
^https?:\/\/ifengad\.3g\.ifeng\.com\/ad\/pv\.php\?stat= - reject
^https?:\/\/iflow\.uczzd\.cn\/log\/ - reject
^https?:\/\/ih2\.ireader\.com\/zyapi\/bookstore\/ad\/ - reject
^https?:\/\/ih2\.ireader\.com\/zyapi\/self\/screen\/ad - reject
^https?:\/\/ih2\.ireader\.com\/zycl\/api\/ad\/ - reject
^https?:\/\/iis1\.deliver\.ifeng\.com\/getmcode\?adid= - reject
^https?:\/\/image1\.chinatelecom-ec\.com\/images\/.*?\/client\w+\.jpg - reject
^https?:\/\/image1\.chinatelecom-ec\.com\/images\/.+?\/\d{13}\.jpg - reject
^https?:\/\/image\.airav\.cc\/AirADPic\/.+?\.gif - reject
^https?:\/\/image\.suning\.cn\/uimg\/ma\/ad\/ - reject
^https?:\/\/images\.91160\.com\/primary\/ - reject
^https?:\/\/images\.client\.vip\.xunlei\.com\/.+?\/advert\/ - reject
^https?:\/\/images\.kartor\.cn\/.+?\.html - reject
^https?:\/\/imeclient\.openspeech\.cn\/adservice\/ - reject
^https?:\/\/img-ys011\.didistatic\.com\/static\/ad_oss\/image-\d{4}-\d{4}\/ - reject
^https?:\/\/img01\.10101111cdn\.com\/adpos\/ - reject
^https?:\/\/img01\.10101111cdn\.com\/adpos\/share\/ - reject
^https?:\/\/img1\.126\.net\/.+?dpi=\w{7,8} - reject
^https?:\/\/img1\.126\.net\/channel14\/ - reject
^https?:\/\/img\.53site\.com\/Werewolf\/AD\/ - reject
^https?:\/\/img\.ddrk\.me\/ad190824 - reject
^https?:\/\/img\.ddrk\.me\/cover\.png - reject
^https?:\/\/img\.ihytv\.com\/material\/adv\/img\/ - reject
^https?:\/\/img\.jiemian\.com\/ads\/ - reject
^https?:\/\/img\.meituan\.net\/(adunion|display|dpmobile|midas)\/\w+\.(gif|jpg|jpg\.webp)$ - reject
^https?:\/\/img\.meituan\.net\/(adunion|display|midas)\/.+?\.(gif|jpg|jpg\.webp)$ - reject
^https?:\/\/img\.meituan\.net\/(display|midas)\/.+?\.(gif|jpg) - reject
^https?:\/\/img\.meituan\.net\/midas\/ - reject
^https?:\/\/img\.rr\.tv\/banner\/.+?\.jpg - reject
^https?:\/\/img\.yun\.01zhuanche\.com\/statics\/app\/advertisement\/.+?-750-1334 - reject
^https?:\/\/img\.zuoyebang\.cc\/zyb-image[\s\S]*?\.jpg - reject
^https?:\/\/img\d+\.10101111cdn\.com\/adpos\/ - reject
^https?:\/\/img\d+\.360buyimg\.com\/jddjadvertise\/ - reject
^https?:\/\/img\d\.doubanio\.com\/view\/dale-online\/dale_ad\/ - reject
^https?:\/\/img\d{2}\.ddimg\.cn\/upload_img\/.+?\/670x900 - reject
^https?:\/\/img\d{2}\.ddimg\.cn\/upload_img\/.+?\/750x1064 - reject
^https?:\/\/img\w\.g\.pptv\.com - reject
^https?:\/\/imgcache\.qq\.com\/qqlive\/ - reject
^https?:\/\/impservice.+?youdao.com - reject
^https?:\/\/impservice\.dictapp\.youdao\.com\/imp\/request - reject
^https?:\/\/interface(\d)?\.music\.163\.com/eapi/(ad|abtest|sp|hot|store|search/(specialkeyword|defaultkeyword|hot)) - reject
^https?:\/\/intl\.iqiyi\.com\/ad_external\/ - reject
^https?:\/\/intl\.iqiyi\.com\/video\/advertise - reject
^https?:\/\/ios\.lantouzi\.com\/api\/startpage - reject
^https?:\/\/ios\.wps\.cn\/ad-statistics-service - reject
^https?:\/\/iphone265g\.com\/templates\/iphone\/bottomAd\.js - reject
^https?:\/\/issuecdn\.baidupcs\.com\/issue\/netdisk\/(guanggao|ts_ad)\/ - reject
^https?:\/\/itunes\.apple\.com\/lookup\?id=575826903 - reject
^https?:\/\/ivy\.pchouse\.com\.cn\/adpuba\/ - reject
^https?:\/\/jxd524\.github\.io\/iFreeTime\/xid32uxaoecnfv2\/ - reject
^https?:\/\/kano\.guahao\.cn\/.+?\?resize=\d{3}-\d{4} - reject
^https?:\/\/learn\.chaoxing\.com\/apis\/service\/appConfig\? - reject
^https?:\/\/list-app-m\.i4\.cn\/getopfstadinfo\.xhtml - reject
^https?:\/\/lives\.l\.qq\.com\/livemsg\?sdtfrom= - reject
^https?:\/\/log.+?baidu\.com - reject
^https?:\/\/log\..+?\.baidu\.com - reject
^https?:\/\/m.+?\.china\.com\.cn\/statics\/sdmobile\/js\/ad - reject
^https?:\/\/m.+?\.china\.com\.cn\/statics\/sdmobile\/js\/mobile\.advert\.js - reject
^https?:\/\/m1\.ad\.10010\.com\/noticeMag\/images\/imageUpload\/2\d{3} - reject
^https?:\/\/m5\.amap\.com\/ws\/valueadded\/ - reject
^https?:\/\/m\.360buyimg\.com\/mobilecms\/s640x1136_jfs\/ - reject
^https?:\/\/m\.airav\.cc\/images\/Mobile_popout_cn\.gif - reject
^https?:\/\/m\.aty\.sohu\.com\/openload? - reject
^https?:\/\/m\.caijing\.com\.cn\/startup_ad_ios\.html$ - reject
^https?:\/\/m\.client\.10010\.com\/mobileService\/(activity|customer)\/(accountListData|get_client_adv|get_startadv) - reject
^https?:\/\/m\.client\.10010\.com\/mobileService\/customer\/getclientconfig\.htm - reject
^https?:\/\/m\.client\.10010\.com\/uniAdmsInterface\/(getHomePageAd|getWelcomeAd) - reject
^https?:\/\/m\.coolaiy\.com\/b\.php - reject
^https?:\/\/m\.creditcard\.ecitic\.com\/.*?\/appStartAdv - reject
^https?:\/\/m\.creditcard\.ecitic\.com\/citiccard\/mbk\/.+?\/appStartAdv - reject
^https?:\/\/m\.creditcard\.ecitic\.com\/citiccard\/mbk\/appspace-client\/cr\/sys\/popAdv - reject
^https?:\/\/m\.creditcard\.ecitic\.com\/citiccard\/mbk\/appspace-getway\/getWay\/appspace-system-web\/cr\/v5\/appStartAdv - reject
^https?:\/\/m\.ctrip\.com\/restapi\/soa2\/\d+\/json\/getAdsList - reject
^https?:\/\/m\.elecfans\.com\/static\/js\/ad\.js - reject
^https?:\/\/m\.ibuscloud.com\/v2\/app\/getStartPage - reject
^https?:\/\/m\.tuniu\.com\/api\/operation\/splash\/ - reject
^https?:\/\/m\.yhdm\.io\/bar\/yfgg.js - reject
^https?:\/\/m\.yhdm\.io\/bar\/yfyh.js - reject
^https?:\/\/m\.youku\.com\/video\/libs\/iwt\.js - reject
^https?:\/\/m\d\.amap\.com\/ws\/valueadded\/alimama\/splash_screen\/ - reject
^https?:\/\/ma\.ofo\.com\/adImage\/ - reject
^https?:\/\/ma\.ofo\.com\/ads - reject
^https?:\/\/mage\.if\.qidian\.com\/Atom\.axd\/Api\/Client\/GetConfIOS - reject
^https?:\/\/mage\.if\.qidian\.com\/argus\/api\/v\d\/client\/getsplashscreen - reject
^https?:\/\/maicai\.api\.ddxq\.mobi\/advert\/ - reject
^https?:\/\/mangaapi\.manhuaren\.com\/v\d\/public\/getStartPageAds - reject
^https?:\/\/mapi\.dangdang\.com\/index\.php\?action=init - reject
^https?:\/\/mapi\.mafengwo\.cn\/ad\/ - reject
^https?:\/\/mapi\.mafengwo\.cn\/travelguide\/ad\/ - reject
^https?:\/\/mbl\.56\.com\/config\/v1\/common\/config\.union\.ios\.do? - reject
^https?:\/\/mcupdate\.gstarcad\.com\/api\/v2\/ - reject
^https?:\/\/media\.qyer\.com\/ad\/ - reject
^https?:\/\/mi\.gdt\.qq\.com\/gdt_mview\.fcg - reject
^https?:\/\/mime\.baidu\.com\/v\d\/IosStart\/getStartInfo$ - reject
^https?:\/\/mime\.baidu\.com\/v\d\/activity\/advertisement - reject
^https?:\/\/mimg\.127\.net\/external\/smartpop-manger\.min\.js - reject
^https?:\/\/mlife\.jf365\.boc\.cn\/AppPrj\/FirstPic\.do\? - reject
^https?:\/\/mm\.app\.joox\.com\/billsrv\/clientBatchAdReport - reject
^https?:\/\/mm\.app\.joox\.com\/retrieval\/getAd - reject
^https?:\/\/mmg\.aty\.sohu\.com\/mqs? - reject
^https?:\/\/mmg\.aty\.sohu\.com\/pvlog? - reject
^https?:\/\/mmgr\.gtimg\.com\/gjsmall\/qiantu\/upload\/ - reject
^https?:\/\/mmgr\.gtimg\.com\/gjsmall\/qqpim\/public\/ios\/splash\/.+?\/\d{4}_\d{4} - reject
^https?:\/\/mob\.mddcloud\.com\.cn\/api\/(ad|advert)\/ - reject
^https?:\/\/mobi\.360doc\.com\/v\d{2}\/Ajax\/festival\.ashx\?op=getfestivaltheme - reject
^https?:\/\/mobile-api2011.elong.com\/(adgateway|adv)\/ - reject
^https?:\/\/mobile-pic\.cache\.iciba\.com\/feeds_ad\/ - reject
^https?:\/\/mobileapi-v6\.elong\.com\/adgateway\/ - reject
^https?:\/\/mp\.weixin\.qq.com\/mp\/ad_complaint - reject
^https?:\/\/mp\.weixin\.qq.com\/mp\/ad_video - reject
^https?:\/\/mp\.weixin\.qq.com\/mp\/advertisement_report - reject
^https?:\/\/mp\.weixin\.qq\.com\/(s|mp)\/(ad_|advertisement|getappmsgad|report|appmsgreport|appmsgpicreport) - reject
^https?:\/\/mpcs\.suning\.com\/mpcs\/dm\/getDmInfo - reject
^https?:\/\/mps\.95508\.com\/mps\/club\/cardPortals\/adv\/\d{25}\.(png|jpg) - reject
^https?:\/\/mrobot\.pcauto\.com\.cn\/v\d\/ad2p - reject
^https?:\/\/mrobot\.pcauto\.com\.cn\/xsp\/s\/auto\/info\/preload\.xsp - reject
^https?:\/\/mrobot\.pconline\.com\.cn\/s\/onlineinfo\/ad\/ - reject
^https?:\/\/mrobot\.pconline\.com\.cn\/v\d\/ad2p - reject
^https?:\/\/ms\.jr\.jd\.com\/gw\/generic\/aladdin\/(new)?na\/m\/getLoadingPicture - reject
^https?:\/\/ms\.jr\.jd\.com\/gw\/generic\/base\/(new)?na\/m\/adInfo - reject
^https?:\/\/msspjh\.emarbox\.com\/getAdConfig - reject
^https?:\/\/mtteve\.beacon\.qq\.com\/analytics - reject
^https?:\/\/newapp\.szsmk\.com\/app\/config\/.*?Ad - reject
^https?:\/\/news\.ssp\.qq\.com\/app - reject
^https?:\/\/nex\.163\.com\/q - reject
^https?:\/\/nnapp\.cloudbae\.cn(:\d+)?\/mc\/api\/advert - reject
^https?:\/\/nnapp\.cloudbae\.cn\/mc\/api\/advert/ - reject
^https?:\/\/nochange\.ggsafe\.com\/ad\/ - reject
^https?:\/\/notch\.qdaily\.com\/api\/v\d\/boot_ad - reject
^https?:\/\/notice\.send-anywhere\.com\/banner - reject
^https?:\/\/oimage([a-z])([0-9])\.ydstatic\.com\/.+?adpublish - reject
^https?:\/\/oimage\w\d\.ydstatic\.com\/image\?.+?=adpublish - reject
^https?:\/\/open\.qyer\.com\/qyer\/config\/get - reject
^https?:\/\/open\.qyer\.com\/qyer\/startpage\/ - reject
^https?:\/\/optimus-ads\.amap\.com\/uploadimg\/ - reject
^https?:\/\/oral\.youdao\.com\/oral\/adInfo - reject
^https?:\/\/oset-api\.open-adx\.com\/ad\/ - reject
^https?:\/\/overseas\.weico\.cc\/portal\.php\?a=get_coopen_ads - reject
^https?:\/\/p[^4](c)?\.music\.126\.net\/\w+==\/10995\d{13}\.jpg$ - reject
^https?:\/\/p\.c\.music\.126.net\/.*?jpg$ - reject
^https?:\/\/p\.du\.163\.com\/ad\/ - reject
^https?:\/\/p\.kuaidi100\.com\/mobile\/(mainapi|mobileapi)\.do - reject
^https?:\/\/p\d.meituan.net\/movie\/.*?\?may_covertWebp - reject
^https?:\/\/p\d\.meituan\.net\/(bizad|wmbanner)\/\w+\.jpg - reject
^https?:\/\/p\d\.meituan\.net\/(mmc|wmbanner)\/ - reject
^https?:\/\/p\d\.meituan\.net\/movie\/\w+\.jpg\?may_covertWebp - reject
^https?:\/\/p\d\.meituan\.net\/wmbanner\/[A-Za-z0-9]+\.jpg - reject
^https?:\/\/p\d\.music\.126\.net\/\w+==\/\d+\.jpg$ - reject
^https?:\/\/p\d{1}\.meituan\.net\/(adunion|display|mmc|wmbanner)\/ - reject
^https?:\/\/pagead2\.googlesyndication\.com\/pagead\/ - reject
^https?:\/\/pan-api\.bitqiu\.com\/activity\/(getPromoteGuide|getUrlList) - reject
^https?:\/\/pan\.baidu\.com\/act\/api\/activityentry - reject
^https?:\/\/pan\.baidu\.com\/rest\/2\.0\/pcs\/adx - reject
^https?:\/\/paopao\w?.qiyipic.com - reject
^https?:\/\/pb\d\.pstatp\.com\/origin - reject
^https?:\/\/pcvideoyd\.titan\.mgtv\.com\/pb\/ - reject
^https?:\/\/photocdn\.sohu\.com\/tvmobilemvms - reject
^https?:\/\/pic1\.chelaile\.net\.cn\/adv\/ - reject
^https?:\/\/pic1cdn\.cmbchina\.com\/appinitads\/ - reject
^https?:\/\/pic\.edaijia\.cn\/adsplash\/ - reject
^https?:\/\/pic\.k\.sohu\.com\/img\d\/wb\/tj\/ - reject
^https?:\/\/pic\.xiami\.net\/images\/common\/uploadpic[\s\S]*?\.jpg$ - reject
^https?:\/\/pic\d\.ajkimg\.com\/mat\/\w+\?imageMogr\d\/format\/jpg\/thumbnail\/\d{3}x\d{4}$ - reject
^https?:\/\/player\.hoge\.cn\/advertisement\.swf - reject
^https?:\/\/pocketuni\.net\/\?app=api&mod=Message&act=ad - reject
^https?:\/\/portal-xunyou\.qingcdn\.com\/api\/v\d\/ios\/ads\/ - reject
^https?:\/\/portal-xunyou\.qingcdn\.com\/api\/v\d\/ios\/configs\/(splash_ad|ad_urls) - reject
^https?:\/\/premiumyva\.appspot\.com\/vmclickstoadvertisersite - reject
^https?:\/\/prom\.mobile\.gome\.com\.cn\/mobile\/promotion\/promscms\/sale\w+\.jsp - reject
^https?:\/\/pss\.txffp\.com\/piaogen\/images\/launchScreen/ - reject
^https?:\/\/ptmpcap\.caocaokeji\.cn\/advert-bss\/ - reject
^https?:\/\/qidian\.qpic\.cn\/qidian_common - reject
^https?:\/\/qt\.qq\.com\/lua\/mengyou\/get_splash_screen_info - reject
^https?:\/\/qzonestyle\.gtimg\.cn\/qzone\/biz\/gdt\/mob\/sdk\/ios\/v2\/ - reject
^https?:\/\/r1\.ykimg\.com\/\w{30,35}\.jpg - reject
^https?:\/\/r1\.ykimg\.com\/material\/.+?\/\d{3,4}-\d{4} - reject
^https?:\/\/r1\.ykimg\.com\/material\/.+?\/\d{6}\/\d{4}\/ - reject
^https?:\/\/r\.inews\.qq\.com\/(adsBlacklist|getBannerAds|getFullScreenPic|getNewsRemoteConfig|getQQNewsRemoteConfig|searchHotCatList|upLoadLoc) - reject
^https?:\/\/r\.inews\.qq\.com\/getSplash\?apptype=ios&startarticleid=&__qnr= - reject
^https?:\/\/r\.inews\.qq\.com\/searchHotCatList - reject
^https?:\/\/r\.inews\.qq\.com\/upLoadLoc - reject
^https?:\/\/r\.l\.youku\.com\/rec_at_click - reject
^https?:\/\/render\.alipay\.com\/p\/s\/h5data\/prod\/spring-festival-2019-h5data\/popup-h5data\.json - reject
^https?:\/\/res-release\.wuta-cam\.com\/json\/ads_component_cache\.json - reject
^https?:\/\/res\.kfc\.com\.cn\/advertisement\/ - reject
^https?:\/\/res\.mall\.10010\.cn\/mall\/common\/js\/fa\.js?referer= - reject
^https?:\/\/res\.xiaojukeji\.com\/resapi\/activity\/get(Ruled|Preload|PasMultiNotices) - reject
^https?:\/\/res\.xiaojukeji\.com\/resapi\/activity\/mget - reject
^https?:\/\/ress\.dxpmedia\.com\/appicast\/ - reject
^https?:\/\/restapi\.iyunmai\.com\/api\/ios\/ad\/ - reject
^https?:\/\/rich\.kuwo\.cn\/AdService\/kaiping\/adinfo - reject
^https?:\/\/richmanapi\.jxedt\.com\/api\/(ad|adplus|guideplus|banadplus) - reject
^https?:\/\/richmanapi\.jxedt\.com\/api\/ad\/guideplus - reject
^https?:\/\/richmanapi\.jxedt\.com\/api\/banadplus - reject
^https?:\/\/richmanmain\.jxedt\.com\/advertisement\/fallback - reject
^https?:\/\/rm\.aarki\.net\/v1\/ads - reject
^https?:\/\/rtbapi.douyucdn.cn\/japi\/sign\/app\/getinfo - reject
^https?:\/\/s0\.2mdn\.net\/ads\/ - reject
^https?:\/\/s1\.api\.tv\.itc\.cn\/v\d\/mobile\/control\/switch\.json - reject
^https?:\/\/s3\.pstatp\.com\/inapp\/TTAdblock\.css - reject
^https?:\/\/s3plus\.meituan\.net\/v1\/mss_a002 - reject
^https?:\/\/s\.go\.sohu\.com\/adgtr\/\?gbcode= - reject
^https?:\/\/s\.go\.sohu\.com\/adgtr\/\?gbcode=(ps|sv|offnavi|newvector|ulog\.imap|newloc)(\.map)?\.(baidu|n\.shifen)\.com - reject
^https?:\/\/s\d\.zdmimg\.com\/www\/api\/v\d\/api\/thirdAd\.php - reject
^https?:\/\/sa\d\.tuisong\.baidu\.com - reject
^https?:\/\/saad\.ms\.zhangyue\.net\/ad - reject
^https?:\/\/sapi\.guopan\.cn\/get_buildin_ad - reject
^https?:\/\/sax\w?\.sina\.cn - reject
^https?:\/\/sax\w?\.sina\.com\.cn - reject
^https?:\/\/sdk\.99shiji\.com\/ad\/ - reject
^https?:\/\/sdkapp\.uve\.weibo\.com\/interface\/sdk\/(actionad|sdkad)\.php - reject
^https?:\/\/sdkapp\.uve\.weibo\.com\/interface\/sdk\/sdkad\.php - reject
^https?:\/\/server-\w+.imrworldwide.com - reject
^https?:\/\/service\.4gtv\.tv\/4gtv\/Data\/(GetAD|ADLog) - reject
^https?:\/\/service\.iciba\.com\/popo\/open\/screens\/v\d\?adjson - reject
^https?:\/\/sf.*?-ttcdn-tos\.pstatp\.com\/obj\/ad - reject
^https?:\/\/sf\w-ttcdn-tos\.pstatp\.com\/obj\/web\.business\.image - reject
^https?:\/\/shimo\.im\/api\/ads\?(.+?) - reject
^https?:\/\/show\.api\.moji\.com\/json\/showcase\/getAll - reject
^https?:\/\/shp\.qpic\.cn\/pggamehead\/.*?h=\d{4} - reject
^https?:\/\/simg\.s\.weibo\.com\/.+?_ios\d{2}\.gif - reject
^https?:\/\/slapi.oray.net/client/ad - reject
^https?:\/\/slapi\.oray\.net\/adver - reject
^https?:\/\/slapi\.oray\.net\/client\/ad - reject
^https?:\/\/sm\.domobcdn\.com\/ugc\/\w\/ - reject
^https?:\/\/smart\.789\.image\.mucang\.cn\/advert - reject
^https?:\/\/smkmp\.96225\.com\/smkcenter\/ad/ - reject
^https?:\/\/smusic\.app\.wechat\.com\/commonCgi\/advertisement\/get_orint_egg$ - reject
^https?:\/\/snailsleep\.net\/snail\/v1\/adTask\/ - reject
^https?:\/\/snailsleep\.net\/snail\/v\d\/screen\/qn\/get\? - reject
^https?:\/\/sp\.kaola\.com\/api\/openad - reject
^https?:\/\/splashqqlive\.gtimg\.com\/website\/\d{6} - reject
^https?:\/\/ss0\.bdstatic\.com/.+?_\d{3}_\d{4}\.jpg - reject
^https?:\/\/ssl\.kohsocialapp\.qq\.com:\d+\/game\/buttons - reject
^https?:\/\/sso\.ifanr\.com\/jiong\/IOS\/appso\/splash\/ - reject
^https?:\/\/sso\.lxjapp\.com\/\/chims\/servlet\/csGetLatestSoftwareVersionServlet - reject
^https?:\/\/stat\.moji\.com - reject
^https?:\/\/statc\.mytuner\.mobi\/media\/banners\/ - reject
^https?:\/\/static\.api\.m\.panda\.tv\/index\.php\?method=clientconf\.firstscreen&__version=(play_cnmb|(\d+\.){0,3}\d+)&__plat=ios&__channel=appstore - reject
^https?:\/\/static\.cnbetacdn\.com\/assets\/adv - reject
^https?:\/\/static\.iask\.cn\/m-v20161228\/js\/common\/adAudit\.min\.js - reject
^https?:\/\/static\.vuevideo\.net\/styleAssets\/.+?\/splash_ad - reject
^https?:\/\/static\.vuevideo\.net\/styleAssets\/advertisement\/ - reject
^https?:\/\/staticlive\.douyucdn\.cn\/.+?\/getStartSend - reject
^https?:\/\/staticlive\.douyucdn\.cn\/upload\/signs\/ - reject
^https?:\/\/stats\.tubemogul\.com\/stats\/ - reject
^https?:\/\/status\.boohee\.com\/api\/v\d\/app_square\/start_up_with_ad - reject
^https?:\/\/storage\.360buyimg\.com\/kepler-app - reject
^https?:\/\/storage\.wax\.weibo\.com\/\w+\.(png|jpg|mp4) - reject
^https?:\/\/support\.you\.163\.com\/xhr\/boot\/getBootMedia\.json - reject
^https?:\/\/supportda\.ofo\.com\/adaction\? - reject
^https?:\/\/szextshort\.weixin\.qq\.com\/cgi-bin\/mmoc-bin\/ad\/ - reject
^https?:\/\/t\d{2}\.baidu\.com - reject
^https?:\/\/tb1\.bdstatic\.com\/tb\/cms\/ngmis\/adsense\/*\.jpg - reject
^https?:\/\/tb2\.bdstatic\.com\/tb\/mobile\/spb\/widget\/jump - reject
^https?:\/\/thor\.weidian\.com\/ares\/home\.splash\/ - reject
^https?:\/\/tiasdk\.app\.wechat\.com\/retrieval\/getAdInfo$ - reject
^https?:\/\/tiku\.zhan\.com\/Common\/newAd\/ - reject
^https?:\/\/tj\.playcvn\.com\/app\/ads\? - reject
^https?:\/\/tqt\.weibo\.cn\/.+?advert\.index - reject
^https?:\/\/tqt\.weibo\.cn\/api\/advert\/ - reject
^https?:\/\/tqt\.weibo\.cn\/overall\/redirect\.php\?r=(tqt_sdkad|tqtad) - reject
^https?:\/\/tracker-download\.oss-cn-beijing\.aliyuncs\.com\/SIMPlus\/ad_ - reject
^https?:\/\/u1\.img\.mobile\.sina\.cn\/public\/files\/image\/\d{3}x\d{2,4}.+?(png|jpg|mp4) - reject
^https?:\/\/u\d\.iqiyipic\.com\/image\/[\w\/]+\/oad_ - reject
^https?:\/\/ugc\.moji001\.com\/sns\/json\/profile\/get_unread - reject
^https?:\/\/ulogs\.umeng\.com - reject
^https?:\/\/ulogs\.umengcloud\.com - reject
^https?:\/\/update\.pan\.baidu\.com\/statistics - reject
^https?:\/\/ups\.youku\.com\/.*?needad=1& - reject
^https?:\/\/v\.17173\.com\/api\/Allyes\/ - reject
^https?:\/\/v\.cctv\.com\/.+?850 - reject
^https?:\/\/v\.icbc\.com\.cn\/userfiles\/Resources\/WAP\/advertisement\/ - reject
^https?:\/\/video\.dispatch\.tc\.qq\.com\/\w+\.p20\d\.1\.mp4 - reject
^https?:\/\/vv\.video\.qq\.com\/getvmind\? - reject
^https?:\/\/wap\.js\.10086\.cn\/jsmccClient\/cd\/market_content\/api\/v\d\/market_content\.page\.query - reject
^https?:\/\/wap\.ngchina\.cn\/news\/adverts\/ - reject
^https?:\/\/wapwenku\.baidu\.com\/view\/fengchaoTwojump\/ - reject
^https?:\/\/wapwenku\.baidu\.com\/view\/fengchao\/ - reject
^https?:\/\/wbapp\.uve\.weibo\.com\/wbapplua\/wbpullad\.lua - reject
^https?:\/\/web\.chelaile\.net\.cn\/api\/adpub\/ - reject
^https?:\/\/webboot\.zhangyue\.com\/zycl\/api\/ad\/ - reject
^https?:\/\/weibointl\.api\.weibo\.cn\/portal\.php\?a=get_coopen_ads - reject
^https?:\/\/weicoapi\.weico\.cc\/img\/ad\/ - reject
^https?:\/\/wenku\.baidu\.com\/shifen\/ - reject
^https?:\/\/werewolf\.53site\.com\/Werewolf\/.+?\/getAdvertise\.php - reject
^https?:\/\/werewolf\.53site\.com\/Werewolf\/.+?\/getShareVideodb\.php - reject
^https?:\/\/wmapi\.meituan\.com\/api\/v\d\/startpicture - reject
^https?:\/\/wmedia-track\.uc\.cn - reject
^https?:\/\/www.baidu.com\/?action=static&ms=1&version=css_page_2@0.*? - reject
^https?:\/\/www.icourse163.org\/.*?(Advertisement) - reject
^https?:\/\/www1\.elecfans\.com\/www\/delivery\/ - reject
^https?:\/\/www\.babyye\.com\/b\.php - reject
^https?:\/\/www\.bldimg\.com/(background|splash)/.+?\.png$ - reject
^https?:\/\/www\.bodivis\.com\.cn\/app\/splashAdvertise - reject
^https?:\/\/www\.cmbc\.com\.cn\/m\/image\/loadingpage\/ - reject
^https?:\/\/www\.cntv\.cn\/nettv\/adp\/ - reject
^https?:\/\/www\.dandanzan\.com\/res\/gdsefse\.js - reject
^https?:\/\/www\.didapinche\.com\/app\/adstat\/ - reject
^https?:\/\/www\.duokan\.com/pictures? - reject
^https?:\/\/www\.duokan\.com/promotion_day - reject
^https?:\/\/www\.flyertea\.com\/source\/plugin\/mobile\/mobile\.php\?module=advis - reject
^https?:\/\/www\.ft\.com\/__origami\/service\/image\/v2\/images\/raw\/https%3A%2F%2Fcreatives\.ftimg\.net%2Fads* - reject
^https?:\/\/www\.gwv7\.com\/b\.php - reject
^https?:\/\/www\.hxeduonline\.com\/mobileapi2\/index\.php\?act=index&op=interdict - reject
^https?:\/\/www\.icourse163\.org\/mob\/j\/v1\/mobRecommendRPCBean\.getMaxWeightAdvertisement\.rpc - reject
^https?:\/\/www\.inoreader\.com\/adv\/ - reject
^https?:\/\/www\.iyingdi\.cn\/ad - reject
^https?:\/\/www\.lianbijr\.com\/adPage\/ - reject
^https?:\/\/www\.likeji\.net\/b\.php - reject
^https?:\/\/www\.meituan\.com\/api\/v\d\/appstatus\? - reject
^https?:\/\/www\.myhug\.cn\/ad\/ - reject
^https?:\/\/www\.nfmovies\.com\/pic\/tu\/ - reject
^https?:\/\/www\.nfmovies\.com\/templets\/default\/images\/logos - reject
^https?:\/\/www\.nfmovies\.com\/uploads\/images\/play\.jpg - reject
^https?:\/\/www\.oschina\.net\/action\/apiv2\/get_launcher - reject
^https?:\/\/www\.shihuo\.cn\/app\d\/saveAppInfo - reject
^https?:\/\/www\.tsytv\.com\.cn\/api\/app\/ios\/ads - reject
^https?:\/\/www\.xiaohongshu\.com\/api\/sns\/v\d\/system_service\/splash_config - reject
^https?:\/\/www\.zybang\.com\/adx\/ - reject
^https?:\/\/xyst\.yuanfudao\.com\/iphone\/splashesV\d - reject
^https?:\/\/xyz\.cnki\.net\/resourcev7\/api\/manualpush\/SlidsList$ - reject
^https?:\/\/y\.gtimg\.cn\/music\/.*?_Ad/\d+\.png - reject
^https?:\/\/y\.gtimg\.cn\/music\/common\/upload\/t_splash_info\/ - reject
^https?:\/\/y\.gtimg\.cn\/music\/common\/upload\/targeted_ads - reject
^https?:\/\/yxyapi\d\.drcuiyutao\.com\/yxy-api-gateway\/api\/json\/advert\/ - reject
^https?:\/\/zt-app\.go189\.cn\/zt-app\/welcome\/.*?Animation - reject

[SSID Setting]
"flenser" suspend=true

[MITM]
skip-server-cert-verify = true
tcp-connection = true
hostname = %APPEND% *.atm.youku.com,*.baidu.com,*.beacon.qq.com,*.bebi.com,*.byteoversea.com,*.club,*.com1.z0.glb.clouddn.com,*.fun,*.hxsame.hexun.com,*.iiilab.com,*.iydsj.com,*.k.sohu.com,*.kakamobi.cn,*.kingsoft-office-service.com,*.l.qq.com,*.logic.cpm.cm.kankan.com,*.music.126.net,*.music.127.net,*.musical.ly,*.nfmovies.com,*.ott.cibntv.net,*.pornhub.com,*.snssdk.com,*.tc.qq.com,*.tiktokcdn.com,*.tiktokv.com,*.tv.sohu.com,*.uve.weibo.com,*.weibo.cn,*.wtzw.com,*pi.feng.com,-aweme.snssdk.com,-lark-frontier-hl.snssdk.com,-reading.snssdk.com,101.201.175.228,101.201.62.22,113.105.222.132,113.96.109.*,115.159.231.79,118.178.214.118,119.18.193.135,121.14.89.216,121.9.212.178,122.14.246.33,123.59.30.10,123.59.31.1,14.21.76.30,154.8.131.171,175.102.178.52,182.92.251.113,183.232.237.194,183.232.246.225,183.60.159.227,203.205.255.16,211.98.71.195,211.98.71.196,211.98.71.226,3gimg.qq.com,47.97.20.12,4gimg.map.qq.com,58cdn.com.cn,59.37.96.220,7n.bczcdn.com,a.apicloud.com,a.applovin.com,a.qiumibao.com,a.wkanx.com,aarkissltrial.secure2.footprint.net,acs.m.taobao.com,act.vip.iqiyi.com,activity2.api.ofo.com,ad.api.3g.youku.com,ad.api.moji.com,ad.sina.com,ad.sina.com.cn,adm.10jqka.com.cn,adpai.thepaper.cn,adproxy.autohome.com.cn,adse.com,adse.ximalaya.com,aes.acfun.cn,agent-count.pconline.com.cn,agn.aty.sohu.com,alogs.umeng.co,alogs.umeng.com,amdc.m.taobao.com,ap*.smzdm.com,api*.futunn.com,api-163.biliapi.net,api-mifit*.huami.com,api-new.app.acfun.cn,api-release.wuta-cam.com,api.21jingji.com,api.app.vhall.com,api.applovefrom.com,api.appsdk.soku.com,api.bjxkhc.com,api.caijingmobile.com,api.catch.gift,api.cdmcaac.com,api.chelaile.net.cn,api.club.lenovo.cn,api.cognitive.microsofttranslator.com,api.daydaycook.com.cn,api.douban.com,api.eshimin.com,api.fengshows.com,api.gaoqingdianshi.com,api.gotokeep.com,api.hanju.koudaibaobao.com,api.haohaozhu.cn,api.huomao.com,api.intsig.net,api.ishansong.com,api.izuiyou.com,api.jr.mi.com,api.jxedt.com,api.kkmh.com,api.laifeng.com,api.laosiji.com,api.m.jd.com,api.m.mi.com,api.mddcloud.com.cn,api.meipian.me,api.mgzf.com,api.mh.163.com,api.mobile.youku.com,api.newad.ifeng.com,api.pinduoduo.com,api.psy-1.com,api.qbb6.com,api.qiuduoduo.cn,api.resso.app,api.rr.tv,api.share.mob.com,api.videozhishi.com,api.vistopia.com.cn,api.vnision.com,api.vuevideo.net,api.waitwaitpay.com,api.wallstcn.com,api.wallstreetcn.com,api.xiachufang.com,api.xueqiu.com,api.yangkeduo.com,api.ycapp.yiche.com,api.yizhibo.com,api.youku.com,api.zhuishushenqi.com,api2.helper.qq.com,apimobile.meituan.com,app-api.jinse.com,app-api.niu.com,app.10086.cn,app.58.com,app.api.ke.com,app.ddpai.com,app.m.zj.chinamobile.com,app.mixcapp.com,app.poizon.com,app.relxtech.com,app.stoneread.com,app.variflight.com,app.veryzhun.com,app.wy.guahao.com,app.xinpianchang.com,app.yinxiang.com,app.zhuanzhuan.com,app2.autoimg.cn,app3.qdaily.com,appapi.huazhu.com,appconf.mail.163.com,apprn.pizzahut.com.cn,appsdk.soku.com,appv6.55haitao.com,asewlfjqwlflkew.com,asp.cntv.myalicdn.com,ast.api.moji.com,atrace.chelaile.net.cn,b-api.ins.miaopai.com,b.zhuishushenqi.com,bank.wo.cn,bbs.airav.cc,bbs.tianya.cn,bdsp-x.jd.com,bj.bcebos.com,bla.gtimg.com,book.img.ireader.com,btrace.qq.com,business-cdn.shouji.sogou.com,business.msstatic.com,c.m.163.com,c.minisplat.cn,c.tieba.baidu.com,c1.ifengimg.com,cache.changjingyi.cn,cache.gclick.cn,cap.caocaokeji.cn,capi.douyucdn.cn,capi.mwee.cn,capis*.didapinche.com,ccsp-egmas.sf-express.com,cdn-1rtb.caiyunapp.com,cdn.api.fotoable.com,cdn.dianshihome.com,cdn.kuaidi100.com,cdn.moji.com,cdn.tiku.zhan.com,cdn2.moji002.com,cdnfile1.msstatic.com,channel.beitaichufang.com,chelaile.net.cn,cheyouapi.ycapp.yiche.com,classbox2.kechenggezi.com,client.mail.163.com,client.qunar.com,clientaccess.10086.cn,cloud.189.cn,cms.daydaycook.com.cn,cmsapi.wifi8.com,cmsfile.wifi8.com,cntv.hls.cdn.myqcloud.com,connect.facebook.net,consumer.fcbox.com,counter.ksosoft.com,creatives.ftimg.net,creditcard.ecitic.com,creditcardapp.bankcomm.com,ct.xiaojukeji.com,ctrl.zmzapi.net,d.1qianbao.com,d.sinaimg.cn,d.zhangle.com,daoyu.sdo.com,dapis.mting.info,dd.iask.cn,ddrk.me,dict-mobile.iciba.com,dili.bdatu.com,dimg04.c-ctrip.com,discuz.gtimg.cn,dl.app.gtja.com,dmhy.anoneko.com,dongfeng.alicdn.com,douyucdn.cn,dsa-mfp.fengshows.cn,dsp-impr2.youdao.com,dsp-x.jd.com,dsp.toutiao.com,dssp.stnts.com,du.hupucdn.com,dxy.com,e.dangdang.com,easyreadfs.nosdn.127.net,edit.sinaapp.com,elemecdn.com,emdcadvertise.eastmoney.com,enjoy.abchina.com,erebor.douban.com,exp.3g.ifeng.com,fb.fbstatic.cn,fdfs.xmcdn.com,fds.api.moji.com,fengplus.feng.com,flowplus.meituan.net,fm.fenqile.com,fmapp.chinafamilymart.com.cn,foodie-api.yiruikecorp.com,free.sinaimg.cn,fuss10.elemecdn.com,g.cdn.pengpengla.com,g.tbcdn.cn,g1.163.com,games.mobileapi.hupu.com,gateway.shouqiev.com,gfp.veta.naver.com,ggic.cmvideo.cn,ggv.cmvideo.cn,ggw.cmvideo.cn,ggx.cmvideo.cn,gorgon.youdao.com,gss0.bdstatic.com,gw-passenger.01zhuanche.com,gw.aihuishou.com,gw.csdn.net,haojia.m.smzdm.com,hd.youku.com,heic.alicdn.com,hm.xiaomi.com,home.mi.com,huami.com,hui.sohu.com,huichuan.sm.cn,i.hoopchina.com.cn,i.weiread.qq.com,i.weread.qq.com,i.ys7.com,i1.hoopchina.com.cn,iadmat.a-z*.1267.net,iapi.bishijie.com,ib-soft.net,icc.one,iface.iqiyi.com,iface2.iqiyi.com,ifengad.3g.ifeng.com,iflow.uczzd.cn,ih2.ireader.com,iis1.deliver.ifeng.com,image.airav.cc,image.suning.cn,image1.chinatelecom-ec.com,images.91160.com,images.client.vip.xunlei.com,images.kartor.cn,imeclient.openspeech.cn,img*.10101111cdn.com,img*.360buyimg.com,img*.ddimg.cn,img-ys011.didistatic.com,img.53site.com,img.ddrk.me,img.doubanio.com,img.ihytv.com,img.jiemian.com,img.meituan.net,img.rr.tv,img.umetrip.com,img.yun.01zhuanche.com,img.zuoyebang.cc,img1.126.net,img1.doubanio.com,img3.doubanio.com,imgcache.qq.com,imgw.g.pptv.com,impservice.dictapp.youdao.com,impservice.youdao.com,impserviceyoudao.com,interfac*.music.163.com,intl.iqiyi.com,ios.lantouzi.com,ios.prod.ftl.netflix.com,ios.wps.cn,iphone265g.com,issuecdn.baidupcs.com,ivy.pchouse.com.cn,iydsj.com,iyes.youku.com,jable.tv,jd.com,js.dilidd.com,jump2.bdimg.com,jxd524.github.io,kano.guahao.cn,kaola-haitao.oss.kaolacdn.com,learn.chaoxing.com,list-app-m.i4.cn,logbaidu.com,m*.amap.com,m.360buyimg.com,m.airav.cc,m.aty.sohu.com,m.caijing.com.cn,m.china.com.cn,m.client.10010.com,m.coolaiy.com,m.creditcard.ecitic.com,m.ctrip.com,m.elecfans.com,m.ibuscloud.com,m.poizon.com,m.tuniu.com,m.yap.yahoo.com,m.yhdm.io,m.youdao.com,m.youku.com,m1.ad.10010.com,ma.ofo.com,mage.if.qidian.com,maicai.api.ddxq.mobi,mangaapi.manhuaren.com,mapi.appvipshop.com,mapi.dangdang.com,mapi.mafengwo.cn,mapi.weibo.com,mbl.56.com,mcupdate.gstarcad.com,media.qyer.com,mg.meituan.net,mi.gdt.qq.com,mimg.127.net,mlife.jf365.boc.cn,mmg.aty.sohu.com,mmgr.gtimg.com,mob.mddcloud.com,mob.mddcloud.com.cn,mobi.360doc.com,mobile-api2011.elong.com,mobile-pic.cache.iciba.com,mobileapi-v6.elong.com,mp.weixin.qq.com,mpcs.suning.com,mps.95508.com,mrobot.pcauto.com.cn,mrobot.pconline.com.cn,ms.jr.jd.com,msg.umengcloud.com,msspjh.emarbox.com,newapp.szsmk.com,newclient.map.baidu.com,news.ssp.qq.com,newsso.map.qq.com,nex.163.com,nfmovies.com,nnapp.cloudbae.cn,nnapp.cloudbae.cn:0,nochange.ggsafe.com,notch.qdaily.com,notice.send-anywhere.com,offline.microsofttranslator.com,oimage*.ydstatic.com,open.qyer.com,optimus-ads.amap.com,oral.youdao.com,oset-api.open-adx.com,overseas.weico.cc,p*.meituan.net,p.c.music.126.net,p.doras.api.vcinema.cn,p.du.163.com,p.kuaidi100.com,pagead2.googlesyndication.com,pan-api.bitqiu.com,paopaow.qiyipic.com,pb.pstatp.com,pcvideoyd.titan.mgtv.com,photocdn.sohu.com,pic*.chelaile.net,pic.ajkimg.com,pic.edaijia.cn,pic.xiami.net,pic1.chelaile.net.cn,pic1cdn.cmbchina.com,pic?.ajkimg.com,player.hoge.cn,pocketuni.net,portal-xunyou.qingcdn.com,premiumyva.appspot.com,prom.mobile.gome.com.cn,promo.xueqiu.com,pss.txffp.com,pstatp.com,ptmpcap.caocaokeji.cn,qidian.qpic.cn,qt.qq.com,qzonestyle.gtimg.cn,r.inews.qq.com,r.l.youku.com,r1.ykimg.com,render.alipay.com,res-release.wuta-cam.com,res.kfc.com.cn,res.mall.10010.cn,res.xiaojukeji.com,resrelease.wuta-cam.com,ress.dxpmedia.com,restapi.iyunmai.com,rich.kuwo.cn,richmanapi.jxedt.com,richmanmain.jxedt.com,rm.aarki.net,rtbapi.douyucdn.cn,s*.zdmimg.com,s.go.sohu.com,s0.2mdn.net,s1.api.tv.itc.cn,s3.pstatp.com,s3plus.meituan.net,sa.tuisong.baidu.com,saad.ms.zhangyue.net,sapi.guopan.cn,saxw.sina.cn,saxw.sina.com.cn,sdk.99shiji.com,server-w.imrworldwide.com,service.4gtv.tv,service.iciba.com,sf*ttcdn-tos.pstatp.com,shimo.im,show.api.moji.com,shp.qpic.cn,simg.s.weibo.com,sina.com,slapi.oray.net,sm.domobcdn.com,smallseotools.com,smart.789.image.mucang.cn,smkmp.96225.com,smusic.app.wechat.com,snailsleep.net,snssdk.com,sp.kaola.com,splashqqlive.gtimg.com,ss0.bdstatic.com,ssl.kohsocialapp.qq.com,sso.ifanr.com,sso.lxjapp.com,stat.moji.com,statc.mytuner.mobi,static.api.m.panda.tv,static.cnbetacdn.com,static.iask.cn,static.vuevideo.net,static1.keepcdn.com,staticlive.douyucdn.cn,stats.tubemogul.com,status.boohee.com,storage.360buyimg.com,storage.wax.weibo.com,support.you.163.com,supportda.ofo.com,szextshort.weixin.qq.com,tb1.bdstatic.com,tb2.bdstatic.com,thor.weidian.com,tiasdk.app.wechat.com,tiku.zhan.com,tj.playcvn.com,tracker-download.oss-cn-beijing.aliyuncs.com,trade-acs.m.taobao.com,u*.iqiyipic.com,u1.img.mobile.sina.cn,ugc.moji001.com,ulogs.umeng.com,ulogs.umengcloud.com,update.pan.baidu.com,ups.youku.com,v.17173.com,v.cctv.com,v.icbc.com.cn,video.dispatch.tc.qq.com,vsco.co,vv.video.qq.com,w.cloudfront.net,w.gdt.qq.com,w.jstucdn.com,w.up.qingdaonews.com,w.ximalaya.com,wap.js.10086.cn,wap.ngchina.cn,web.chelaile.net.cn,webboot.zhangyue.com,weibointl.api.weibo.cn,weicoapi.weico.cc,werewolf.53site.com,wmapi.meituan.com,wmedia-track.uc.cn,www.babyye.com,www.bldimg.com,www.bodivis.com.cn,www.cmbc.com.cn,www.cntv.cn,www.dandanzan.com,www.didapinche.com,www.dililitv.com,www.duokan.com,www.facebook.com,www.flyertea.com,www.ft.com,www.gwv7.com,www.hxeduonline.com,www.icourse163.org,www.inoreader.com,www.iyingdi.cn,www.lianbijr.com,www.likeji.net,www.meituan.com,www.myhug.cn,www.oschina.net,www.shihuo.cn,www.tieba.com,www.tsytv.com.cn,www.xiaohongshu.com,www.zybang.com,www1.elecfans.com,xueqiu.com,xyst.yuanfudao.com,xyz.cnki.net,y.gtimg.cn,yxyapi*.drcuiyutao.com,zt-app.go189.cn
ca-passphrase = GeekQu
ca-p12 = MIIKKgIBAzCCCfQGCSqGSIb3DQEHAaCCCeUEggnhMIIJ3TCCBE8GCSqGSIb3DQEHBqCCBEAwggQ8AgEAMIIENQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQISSU7qfQ4bmoCAggAgIIECHnanV7K/vxPK6pjGuKWFiqp6/PK/zvUxUio9U2gO1roW6vrZcIkSKqJcaezIokiQMiVH/e5Iuu2Cblj87UsE6spMHG79ywT08KTHHVym3PfMLLNo+P03Tb3LKfzpbkmsYT6QcYnvzatATSxn37chBnCtCT0/qrQZSQslsjayEQbimGHV8iKQNVwrHu9e85GSDVShJ4ql8e/K73+ioUa4K7U6Bb2TurzvxUq+UWlrXJkCQVO4RwFU1h73+dVqxOxIjvchh3tKAmu8Gt1q5NKHvDO+JuIyv0HtCx+zo7ZEkAVnz8OKg72tbdRve32qPM503omxozZM6mVFVDKx95PyGntlEDcWbpLtkttDkk0vjJZGf98ebumdXTccXN4yO5ymzaq47BSBB5IGYrWdVLA4l/gdDC+8lBRBZ1MkEwS/rMyyD8cacBW4rf7ECyKbYYcS5scaKJnMRP62KTxzzlMDT55U0KPiX6XKK6MWxexvILCuBbKOy4V6j2/+svoBD/FobbhLkQdHELYgIpgBXVcNQPy0aUihP7zYoQ4jtxbcRBwEaqEPHbY8QRpL3fTNuXegnAEzUXiPjfmVcYXlHxyj9OK4PWHH24SvqVWkHsMnSJFmzxU6XqWAUIw2IfOxFfY/9/swRfsNTRQZm6awx6dHDXy/GFAVVbYnyZi8Oh7ZlMQbdQ2bGncEST6PlDyXsxGCp9t/YFOuWY3kMmg8fLfV+IzNcqOoaw45MvZFGaULE/rou1p10rsnQMJDf511uzDEldWzKAJQDYVcSy2qHYlrIFs8NXUts5mH5NtE60xK+zVgqltzKqKYzIfWUXW1jTd/3KFTxs4cS8lHus/b/65qZWf9hwG1823Qi8a1sFCcLKY0G8AclBxcE8J7TUtyDgSh1wS9Bag4maRLJOrb/OkveVGLr8cGASvVIUhCI4XKzC55DOkIAWI5ICUgQT0iPlRNTN3JZG0zOEJY2cyq3BjZhtoYbqJc9pHxvcnXS/R2qrc9Z/UKJA7kSRNQ6xGvnyF8x0HI7RDpAinsseTRM+b2vkUPDEMfqkv0amG8YRcKD5zR8AZZrFh7KVAi/emUd5RIc4xJ5YHXYmoJwVonOUqpyhgHENobcWvAltvKEcNWjCAtvfQD0JnqKalBZDNjWRSadVakOFzgGErWWX/nGlcbuhVpUEaX75lNkFPxk1lurWd3LS676j/8pFjwlK51LhK0GsQH5NbL/WHdGwjJYWRNUU43ayojHEl7idK8dplvlLwHdQfq62cLbH+22nWipABh2mYT8nebyBjylJG+CS4q0Xo5/EOh9Bc6MDaBMU1q/hIZI9FqhX0JcXwQ8DtmJPEkzh0lcd8tsrOE70Pkh0ET75onOczMAyCCTCCBYYGCSqGSIb3DQEHAaCCBXcEggVzMIIFbzCCBWsGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAiBlNdONX/ZKgICCAAEggTI7Ius00a/xRACerwGZdBh/dmILnN82dQ5KGabg8//Lq9h0BA+NcPDCpH+fXZYU0G3Kqo6tNvzN5Lb6IiZy9K4A1jXJjRE6jvkg6Zk4DSfcFwlrLpB1b1JJa9jIRtIjj5Y6T1h+FXHMPRZVf6pkwko/NAXJcXhHQ3eXbWHDzGb06Uo9hcFdjwJCjnSk+SzXAhUUyMJ+bJvdoyGwZGswKZ/Kyalp33eIq2A52wAZ+e2auKJdfK0x+obT3Wr7Zef5HfQFymXoo/3xlfy1xrp7ynj2dNn0bJDekmpnlFD2V+Z9s6nyE5oVqNOwHpCt+MU0P0u97K5Yr10pzsLF9NA/zVzTE3unkk8wFXgxBDbZrkgPMiai+9F+3TaQDIg+1FFPrG2HnThRO99fhCw6qdm+3nl/YOdll4NIEI3aJOc+J6XVn7H7cSupG2DjgHsj10ArJhTVTIaQQRcadT2htTizsClEHjD3RIgx9j7fk3bjEIwybJiQQaZhq0NPmDVh7Tq038XYZWwiwSPQlBY0QDPx00iYDVQWP+UwjqtkHn4f5P6VNHKQVA1NGqhi0NkD43Mivs37kjsRzg34OjjTSEXtAkkHAb4ayKTUbfnwgi3Yoyw8SQu2wUCuLoMuyzvRMpkOLqP7nLzbI8WutRlq2gT+RMh6WJySsoaG8sUJq4lz4rKmBWqs+P4K1YYSbv8mT8+cD5nr9j43V9EH9C4oZ9+VX92aVByppyxsoRgxKmE0zYQ6dEvB3lHBeY51Gu2i+0fePNxXE7NkzUc6Ylw0clnYbZLboUeA0EOW80NNPGZrlq60578xRlUjxIGvTSCvpv+6fJleqv/IBaBAcQ53HdJGRlxpF80FtJh+oiYL8hM4Vsr00CcvZQSBex3sGGduSPzqdj8Z479w8WfCs5XF8Drf9cgVilf2mifcavUvsngqtYnhw140I9fR0RjFEOd/2XUFi6R+Yj3V4V/9aSWcw/lam5XgfilaqOAgxCMM2DnPXK0ATOEW73ozBCzL4jy54OYpNX+RsLk2T9geNzG42RO7TXq9CrV0cAo5QjYDs4slOcL6qxbYcBo6gp80959rk2RZ9F8fCqEYwtEBxyQ4w3R96m6AsV8C3erMeNxAvgah5g4Iq0MusHFuynHHoO8nlp3igx/xGj+DtxSw9AsDGJ/pwD7Fevog1DhoPeMn0BQ1+IxQJHufQ6tHNEkGBXTPISkdRa+oHx8DOtBZcMMvHllc8/MEDctGRvTcKXBmQSb3hWnVQvXDJ7R0nXeHdWkS3i3WzlYgW0KvKOXEF+ruP070QHU/Mzw4tbDiJEB0HgbTpLEpTAuOQHX+e+gfGJzCuROqke11LaXNrrFaycOd5cI5KPGldHHNyChFPkgdIBB5NLCEk1qo89jPJO9G6JsN412bYIxT8UceXWujkfR6bqAG9MlBqlQC2EBHIUQGuTAcgzK30EtUD/ZGeWTAs4GmFVEysUe76bB141a3qIJyKnd+t3EufvXCj/oQinJ+TkSkMc6O/vkHVJwVJ1AkGR9nRoZ3mIK3jKKhzvWxn6S+AzmOX4+9mmzz5mfiUiUMWHR2O7QMPpogEcEF5DSoFLprxp9zKgf2Y2gVUY4j07snigNLKokWxRtHgZTU2KxMWowIwYJKoZIhvcNAQkVMRYEFAbZu85upxbZOSqqmrJzvDh/3VmgMEMGCSqGSIb3DQEJFDE2HjQAVABoAG8AcgAgAFMAUwBMACAAQwBBACAAMQA4AC0AMAA2AC0AMQAzACAAMAAwADoANAA3MC0wITAJBgUrDgMCGgUABBT06JjTEYIxaVzmt4so+1SEMLvkJAQIDVK5cd4NVGU=

[Rule]
RULE-SET,https://raw.githubusercontent.com/lhie1/Rules/master/Surge/Surge%203/Provider/Reject.list,REJECT
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Special.list,DIRECT

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Netflix.list,Netflix
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Spotify.list,Spotify
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Disney%20Plus.list,GlobalTV

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/YouTube%20Music.list,YouTube
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/YouTube.list,YouTube

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/ABC.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Abema%20TV.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Amazon.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Apple%20News.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Apple%20TV.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Bahamut.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/BBC%20iPlayer.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/DAZN.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Discovery%20Plus.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/encoreTVB.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Fox%20Now.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Fox%2B.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/HBO.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Hulu%20Japan.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Hulu.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Japonx.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/JOOX.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/KKBOX.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/KKTV.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Line%20TV.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/myTV%20SUPER.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Pandora.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/PBS.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Pornhub.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Soundcloud.list,GlobalTV
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/ViuTV.list,GlobalTV

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Telegram.list,Telegram
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Steam.list,Steam
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Microsoft.list,Microsoft

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Proxy.list,Proxy

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Apple.list,Apple

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Scholar.list,Proxy

RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Bilibili.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/iQiyi.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Netease%20Music.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Tencent%20Video.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Media/Youku.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Domestic.list,Domestic
RULE-SET,https://cdn.jsdelivr.net/gh/lhie1/Rules@master/Surge/Surge%203/Provider/Domestic%20IPs.list,Domestic
RULE-SET,LAN,DIRECT

GEOIP,CN,Domestic
FINAL,Proxy,dns-failed

[Host]
ip6-localhost = ::1
ip6-loopback = ::1
taobao.com = server:223.6.6.6
*.taobao.com = server:223.6.6.6
tmall.com = server:223.6.6.6
*.tmall.com = server:223.6.6.6
jd.com = server:119.29.29.29
*.jd.com = server:119.28.28.28
*.qq.com = server:119.28.28.28
*.tencent.com = server:119.28.28.28
*.alicdn.com = server:223.5.5.5
aliyun.com = server:223.5.5.5
*.aliyun.com = server:223.5.5.5
weixin.com = server:119.28.28.28
*.weixin.com = server:119.28.28.28
bilibili.com = server:119.29.29.29
*.bilibili.com = server:119.29.29.29
*.hdslb.com = server:119.29.29.29
163.com = server:119.29.29.29
*.163.com = server:119.29.29.29
126.com = server:119.29.29.29
*.126.com = server:119.29.29.29
*.126.net = server:119.29.29.29
*.127.net = server:119.29.29.29
*.netease.com = server:119.29.29.29
mi.com = server:119.29.29.29
*.mi.com = server:119.29.29.29
xiaomi.com = server:119.29.29.29
*.xiaomi.com = server:119.29.29.29
dler.cloud = server:180.76.76.76
dleris.best = server:180.76.76.76
routerlogin.net = server:system
_hotspot_.m2m = server:system
router.asus.com = server:system
hotspot.cslwifi.com = server:system
amplifi.lan = server:system
*.lan = server:system

{% endif %}
{% if request.target == "loon" %}

[General]
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,e.crashlynatics.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system,119.29.29.29,223.5.5.5
allow-udp-proxy = false
host = 127.0.0.1

[Proxy]

[Remote Proxy]

[Proxy Group]

[Rule]

[Remote Rule]

;[URL Rewrite]
;enable = true
;^https?:\/\/(www.)?(g|google)\.cn https://www.google.com 302

[Remote Rewrite]
https://github.com/tnt2ray/tnt2ray/raw/tnt2ray-patch-1/Surge/Rewrite.list,auto

{% endif %}
{% if request.target == "quan" %}

[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}
{% if request.target == "quanx" %}

[general]
excluded_routes=192.168.0.0/16, 172.16.0.0/12, 100.64.0.0/10, 10.0.0.0/8
geo_location_checker=http://ip-api.com/json/?lang=zh-CN, https://github.com/KOP-XIAO/QuantumultX/raw/master/Scripts/IP_API.js
network_check_url=http://www.baidu.com/
server_check_url=http://www.gstatic.com/generate_204

[dns]
server=119.29.29.29
server=223.5.5.5
server=1.0.0.1
server=8.8.8.8

[policy]
static=♻️ 自动选择, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Auto.png
static=🔰 节点选择, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Proxy.png
static=🌍 国外媒体, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/GlobalMedia.png
static=🌏 国内媒体, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/DomesticMedia.png
static=Ⓜ️ 微软服务, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Microsoft.png
static=📲 电报信息, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Telegram.png
static=🍎 苹果服务, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Apple.png
static=🎯 全球直连, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Direct.png
static=🛑 全球拦截, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Advertising.png
static=🐟 漏网之鱼, direct, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Final.png

[server_remote]

[filter_remote]

[rewrite_remote]

[server_local]

[filter_local]

[rewrite_local]

[mitm]

{% endif %}
{% if request.target == "mellow" %}

[Endpoint]
DIRECT, builtin, freedom, domainStrategy=UseIP
REJECT, builtin, blackhole
Dns-Out, builtin, dns

[Routing]
domainStrategy = IPIfNonMatch

[Dns]
hijack = Dns-Out
clientIp = 114.114.114.114

[DnsServer]
localhost
223.5.5.5
8.8.8.8, 53, Remote
8.8.4.4

[DnsRule]
DOMAIN-KEYWORD, geosite:geolocation-!cn, Remote
DOMAIN-SUFFIX, google.com, Remote

[DnsHost]
doubleclick.net = 127.0.0.1

[Log]
loglevel = warning

{% endif %}
{% if request.target == "surfboard" %}

[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
{% if request.target == "sssub" %}
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "ipv6": false,
  "metered": false,
  "proxy_apps": {
    "enabled": false,
    "bypass": true,
    "android_list": [
      "com.eg.android.AlipayGphone",
      "com.wudaokou.hippo",
      "com.zhihu.android"
    ]
  },
  "udpdns": false
}

{% endif %}