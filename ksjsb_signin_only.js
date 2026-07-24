/**
 * 快手极速版 - 仅每日签到 (signin)
 * 对齐原脚本：任务列表 -> triggerTaskAction("signIn") -> signIn/report -> 核对金币
 *
 * 环境变量：
 *   ksck            cookie#salt#代理[可选]  多账号 & 或换行
 *   ksTaskNum       并发，默认 1
 *   ksAccountDelay  账号间隔秒，默认 60-120 随机；0=不等待
 *
 * 依赖：axios、smallfawn、socks-proxy-agent(可选)
 * cron：30 8 * * *
 * new Env("快手极速版每日签到");
 */

"use strict";

const axios = require("axios");

let getSig68;
try {
  ({ getSig68 } = require("smallfawn"));
} catch (e) {
  console.log("❌ 缺少 smallfawn，请先安装后再运行");
  process.exit(1);
}

let SocksProxyAgent = null;
try {
  ({ SocksProxyAgent } = require("socks-proxy-agent"));
} catch (_) {}

const H5_UA_IOS =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.31(0x18001E2D) NetType/WIFI Language/zh_CN";
const REFERER_EARN =
  "https://nebula.kuaishou.com/nebula/task/earning?layoutType=4&hyId=nebula_earning_ug_cdn&source=bottom_guide_second";

const SIGNIN_TASK_ID = 20022;
const SIGNIN_RESOURCE = {
  eventTrackingTaskId: 20022,
  resourceId: "earnPage_cardArea_1",
  extParams: { isServerRecordClickAction: true },
};

const COOKIE_KEYS = [
  "kpn", "kpf", "userId", "did", "c", "appver", "language", "mod", "did_tag",
  "egid", "oDid", "androidApiLevel", "newOc", "browseType", "socName", "ftt",
  "abi", "userRecoBit", "device_abi", "grant_browse_type", "iuid", "rdid",
  "kuaishou.api_st",
];

const COOKIE_DEFAULTS = {
  kpn: "NEBULA",
  c: "XIAOMI",
  language: "zh-cn",
  mod: "Xiaomi(MI 8 Lite)",
  androidApiLevel: "29",
  newOc: "XIAOMI",
  browseType: "3",
  socName: "Qualcomm Snapdragon 660",
  ftt: "1",
  abi: "arm64",
  userRecoBit: "0",
  device_abi: "arm64",
  grant_browse_type: "AUTHORIZED",
  iuid: "1",
  did_tag: "0",
  kpf: "ANDROID_PHONE",
};

function log(...a) {
  console.log(...a);
}
function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function randInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  if (max < min) [min, max] = [max, min];
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function parseAccountDelayMs(raw) {
  if (raw == null || String(raw).trim() === "") return randInt(60, 120) * 1000;
  const s = String(raw).trim();
  if (s === "0") return 0;
  const m = s.match(/^(\d+(?:\.\d+)?)\s*[-~,~～]\s*(\d+(?:\.\d+)?)$/);
  if (m) {
    const a = Math.max(0, Number(m[1]));
    const b = Math.max(0, Number(m[2]));
    return randInt(Math.min(a, b), Math.max(a, b)) * 1000;
  }
  const n = Number(s);
  if (!Number.isNaN(n) && n >= 0) return Math.floor(n * 1000);
  return randInt(60, 120) * 1000;
}
function formatDuration(ms) {
  const sec = Math.round(ms / 1000);
  if (sec < 60) return sec + " 秒";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return s ? m + " 分 " + s + " 秒" : m + " 分钟";
}
function parseAccounts(raw) {
  if (!raw) return [];
  return String(raw)
    .split(/[&\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((line) => {
      const p = line.split("#");
      return { ck: p[0] || "", salt: p[1] || "", proxy: p[2] || "" };
    })
    .filter((a) => a.ck);
}
function parseCookie(ck) {
  const map = {};
  String(ck || "")
    .split(";")
    .forEach((seg) => {
      const i = seg.indexOf("=");
      if (i <= 0) return;
      const k = seg.slice(0, i).trim();
      let v = seg.slice(i + 1).trim();
      if (!k) return;
      try {
        v = decodeURIComponent(v);
      } catch (_) {}
      map[k] = v;
    });
  return map;
}
function fromB64Json(b64) {
  if (b64 == null) return {};
  if (typeof b64 === "object") return b64;
  const s = String(b64);
  try {
    return JSON.parse(Buffer.from(s, "base64").toString("utf8"));
  } catch (_) {
    try {
      return JSON.parse(s);
    } catch {
      return {};
    }
  }
}
function pickSigString(ret) {
  if (ret == null || ret === false) return null;
  if (typeof ret === "string") {
    const s = ret.trim().replace(/^\?/, "");
    return !s || s === "[object Object]" ? null : s;
  }
  if (typeof ret === "number" || typeof ret === "boolean") return String(ret);
  if (typeof ret === "object") {
    if (ret.result != null) {
      const v = pickSigString(ret.result);
      if (v) return v;
    }
    for (const k of ["data", "query", "queryStr", "str", "sign", "sig", "__NS_sig3", "sig3"]) {
      if (ret[k] != null) {
        const v = pickSigString(ret[k]);
        if (v) return v;
      }
    }
    const entries = Object.entries(ret).filter(
      ([, v]) => v != null && ["string", "number", "boolean"].includes(typeof v)
    );
    if (entries.length) {
      return entries
        .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(String(v)))
        .join("&");
    }
  }
  return null;
}

class KsSignAccount {
  constructor(acc, index) {
    this.index = index + 1;
    this.ck = acc.ck;
    this.salt = acc.salt;
    this.proxyRaw = acc.proxy || "";
    this.socks5 = null;
    this.api_st = "";
    this.userId = "";
    this.did = "";
    this.mod = "";
    this.osVersion = "10";
    this.eventTrackingLogInfo = { ...SIGNIN_RESOURCE };
    this.coinBefore = null;
    this.coinAfter = null;
  }

  async request(opt) {
    const conf = {
      timeout: opt.timeout || 30000,
      method: opt.method || "GET",
      url: opt.url,
      headers: opt.headers || {},
      data: opt.data,
      params: opt.params,
      proxy: false,
      validateStatus: () => true,
    };
    if (this.socks5) {
      conf.httpAgent = this.socks5;
      conf.httpsAgent = this.socks5;
    }
    return axios.request(conf);
  }

  prepareCookie() {
    const originalCk = this.ck;
    const map = parseCookie(this.ck);
    if (map.SMPM) delete map.SMPM;
    for (const [k, v] of Object.entries(COOKIE_DEFAULTS)) {
      if (!Object.prototype.hasOwnProperty.call(map, k) || map[k] === "") map[k] = v;
    }
    const must = ["userId", "did", "kuaishou.api_st"];
    const originMap = parseCookie(originalCk);
    const needRebuild = must.some((k) => !originMap[k] && map[k]);
    this.ck = needRebuild
      ? Object.entries(map).map(([k, v]) => k + "=" + v).join("; ")
      : originalCk.replace(/\bSMPM=[^;]*;?\s*/g, "").replace(/;\s*$/, "");

    const m = this.ck.match(/kuaishou\.api_st=([^;]+)/);
    this.api_st = m ? decodeURIComponent(String(m[1] || "").trim()) : "";
    this.userId = map.userId || originMap.userId || "";
    this.did = map.did || originMap.did || "";
    this.mod = map.mod || originMap.mod || COOKIE_DEFAULTS.mod;
    // 从 mod 里粗略抽版本号给 UA 用
    const apiLevel = parseInt(map.androidApiLevel || originMap.androidApiLevel || "29", 10);
    this.osVersion = !Number.isNaN(apiLevel) && apiLevel >= 30 ? "11" : "10";

    return COOKIE_KEYS.filter((k) => !(parseCookie(this.ck)[k] || map[k]));
  }

  randomUserAgentModel() {
    // 原脚本 randomUserAgent() 用于拼 Android UA 设备段
    return (this.mod || "MI 8 Lite").replace(/[()]/g, " ").trim() || "MI 8 Lite";
  }

  actionUA() {
    return (
      "Mozilla/5.0 (Linux; Android " +
      this.osVersion +
      "; " +
      this.randomUserAgentModel() +
      "; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.99 Mobile Safari/537.36 Yoda/3.2.16-rc21 ksNebula/13.9.10.10684 OS_PRO_BIT/64 MAX_PHY_MEM/5724 KDT/PHONE AZPREFIX/az3 ICFO/0 StatusHT/29 TitleHT/44 NetType/WIFI ISLP/0 ISDM/0 ISLB/0 locale/zh-cn SHP/2068 SWP/1080 SD/2.75 CT/0 ISLM/0"
    );
  }

  async setupProxy() {
    if (!this.proxyRaw) {
      log("账号[" + this.index + "] 直连");
      return;
    }
    if (!SocksProxyAgent) {
      log("账号[" + this.index + "] 未安装 socks-proxy-agent，忽略代理");
      return;
    }
    const p = this.proxyRaw;
    try {
      if (p.includes("socks://") || p.includes("socks5://")) {
        this.socks5 = new SocksProxyAgent(p, { timeout: 30000 });
      } else if (p.includes("|") && p.split("|").length === 4) {
        const [hostname, port, username, password] = p.split("|");
        this.socks5 = new SocksProxyAgent(
          { hostname, port, username, password },
          { timeout: 30000 }
        );
      } else {
        log("账号[" + this.index + "] 代理格式错误，直连");
        return;
      }
      await this.request({
        url: "https://www.baidu.com/",
        method: "GET",
        timeout: 15000,
        headers: { "User-Agent": "Mozilla/5.0" },
      });
      log("账号[" + this.index + "] 代理可用");
    } catch (e) {
      this.socks5 = null;
      log("账号[" + this.index + "] 代理失败，改直连: " + e.message);
    }
  }

  b64(obj) {
    return Buffer.from(JSON.stringify(obj)).toString("base64");
  }

  async getSig68(emptyObj, bodyObj, method, type, cookie) {
    try {
      const queryObj = fromB64Json(
        typeof emptyObj === "string" ? emptyObj : this.b64(emptyObj || {})
      );
      const body = fromB64Json(
        typeof bodyObj === "string" ? bodyObj : this.b64(bodyObj || {})
      );
      const m = String(method || "get").toLowerCase();
      const raw = await getSig68(queryObj, body, m, type || "json", cookie || this.ck);
      const sig = pickSigString(raw);
      if (!sig) {
        log(
          "账号[" + this.index + "] getSig68 空结果",
          raw && typeof raw === "object" ? Object.keys(raw) : raw
        );
      }
      return sig;
    } catch (e) {
      log("账号[" + this.index + "] getSig68 异常: " + e.message);
      return null;
    }
  }

  async getTaskList() {
    try {
      const { data } = await this.request({
        method: "GET",
        url: "https://nebula.kuaishou.com/rest/n/nebula/activity/earn/overview/tasks",
        headers: { Cookie: this.ck },
      });
      if (data && data.result == 1) return data.data;
      log(
        "账号[" + this.index + "] 获取任务列表失败: " +
          ((data && (data.errorMsg || data.error_msg)) || JSON.stringify(data))
      );
      return null;
    } catch (e) {
      log("账号[" + this.index + "] 请求任务列表失败: " + e.message);
      return null;
    }
  }

  async userInfoApi(tag) {
    try {
      const { data } = await this.request({
        method: "GET",
        url: "https://nebula.kuaishou.com/rest/n/nebula/activity/earn/overview/basicInfo?source=",
        headers: {
          "User-Agent": H5_UA_IOS,
          Referer: REFERER_EARN,
          Cookie: this.ck,
        },
      });
      if (data && data.data) {
        const nick = (data.data.userData && data.data.userData.nickname) || "";
        const cash = data.data.totalCash;
        const coin = Number(data.data.totalCoin);
        if (tag === "before") this.coinBefore = coin;
        if (tag === "after") this.coinAfter = coin;
        log(
          (tag === "before" ? "------------[" + nick + "]------------\n" : "") +
            "账号[" +
            this.index +
            "] " +
            (tag || "") +
            " 现金【" +
            cash +
            "】金币【" +
            coin +
            "】"
        );
        return { nick, cash, coin, raw: data.data };
      }
      return null;
    } catch (e) {
      log("账号[" + this.index + "] 用户信息失败: " + e.message);
      return null;
    }
  }

  /** 原脚本签到前必须先触发 matrix/resource/action */
  async triggerTaskActionSignIn() {
    const body = {
      actionType: 1,
      resourceSlotInfo: this.eventTrackingLogInfo || SIGNIN_RESOURCE,
    };
    const sig = await this.getSig68({}, body, "POST", "json", this.ck);
    if (!sig) {
      log("账号[" + this.index + "] 签到触发签名失败");
      return false;
    }
    try {
      const { data } = await this.request({
        method: "POST",
        url:
          "https://nebula.kuaishou.com/rest/wd/usergrowth/encourage/matrix/resource/action?" +
          String(sig),
        headers: {
          "User-Agent": this.actionUA(),
          "Content-Type": "application/json",
          Cookie: this.ck,
        },
        data: body,
        timeout: 30000,
      });
      if (data && data.result === 1) {
        log("账号[" + this.index + "] 签到触发成功");
        return true;
      }
      log(
        "账号[" + this.index + "] 签到触发失败: " +
          ((data && (data.errorMsg || data.error_msg)) || JSON.stringify(data))
      );
      return false;
    } catch (e) {
      log("账号[" + this.index + "] 签到触发异常: " + e.message);
      return false;
    }
  }

  async signInReport() {
    const sig = await this.getSig68({}, {}, "GET", "json", this.ck);
    if (!sig) {
      log("账号[" + this.index + "] 获取签到sig失败");
      return null;
    }
    const url =
      "https://nebula.kuaishou.com/rest/wd/encourage/unionTask/signIn/report?" + String(sig);
    try {
      const res = await this.request({
        method: "GET",
        url,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": H5_UA_IOS,
          Referer: REFERER_EARN,
          Cookie: this.ck,
        },
      });
      return res.data;
    } catch (e) {
      log("账号[" + this.index + "] 签到请求异常: " + e.message);
      return null;
    }
  }

  async run() {
    const missing = this.prepareCookie();
    // 仅硬性校验登录关键字段；其余字段用默认值补齐，不阻断
    const hardMissing = ["userId", "did", "kuaishou.api_st"].filter((k) => {
      if (k === "kuaishou.api_st") return !this.api_st;
      return !(this[k] && String(this[k]).trim());
    });
    if (hardMissing.length) {
      log(
        "账号[" +
          this.index +
          "] COOKIE关键字段缺失，停止: " +
          hardMissing.join(", ") +
          (missing.length ? "；其它缺失(已尽量默认): " + missing.join(", ") : "")
      );
      return;
    }
    if (missing.length) {
      log(
        "账号[" +
          this.index +
          "] COOKIE非关键字段缺失(已用默认/忽略): " +
          missing.join(", ")
      );
    }

    await this.setupProxy();
    log("账号[" + this.index + "] userId=" + this.userId + " did=" + (this.did || ""));

    await this.userInfoApi("before");

    // 1) 任务列表：取签到任务状态
    const tasks = await this.getTaskList();
    const signTask =
      (tasks &&
        tasks.dailyTasks &&
        tasks.dailyTasks.find((t) => t && Number(t.id) === SIGNIN_TASK_ID)) ||
      null;

    this.eventTrackingLogInfo = { ...SIGNIN_RESOURCE };
    if (signTask && (signTask.finish === true || signTask.finish === 1 || signTask.finish === "true")) {
      log("账号[" + this.index + "] 今日签到任务已完成(finish=true)，跳过");
      return;
    }
    if (!tasks) {
      log("账号[" + this.index + "] 任务列表不可用，仍按固定 eventTracking 继续签到");
    } else if (!signTask) {
      log("账号[" + this.index + "] 未找到签到任务 id=20022，仍尝试触发+上报");
    }

    // 2) 关键：先 trigger，再 report（与宝箱入账链路一致）
    log("账号[" + this.index + "] 执行签到触发 + 上报");
    const triggered = await this.triggerTaskActionSignIn();
    if (!triggered) {
      log(
        "⚠️ 账号[" +
          this.index +
          "] 签到触发失败，仍尝试 report；若金币不入账通常就是这一步失败"
      );
    }
    await wait(800);

    // 3) report
    const data = await this.signInReport();
    let reportOk = false;
    let amount = null;
    if (data && data.data) {
      reportOk = true;
      try {
        amount =
          data.data.reportRewardResult.eventTrackingAwardInfo.awardInfo[0].amount;
      } catch (_) {}
      log(
        "✅ 账号[" +
          this.index +
          "] 签到接口返回成功 展示奖励 " +
          (amount == null ? "?" : amount) +
          " 金币"
      );
      try {
        log(
          "账号[" +
            this.index +
            "] report 摘要: " +
            JSON.stringify({
              result: data.result,
              hasData: !!data.data,
              reportRewardResult: data.data.reportRewardResult || null,
            }).slice(0, 400)
        );
      } catch (_) {}
    } else if (data && data.result == 50) {
      log(
        "❌ 账号[" +
          this.index +
          "] 签到失败  " +
          (data.error_msg || "") +
          " 请确认CK是否完整/是否被错误编码"
      );
    } else {
      log(
        "❌ 账号[" +
          this.index +
          "] 签到失败  " +
          (typeof data === "string"
            ? data.slice(0, 180)
            : (data && (data.error_msg || data.errorMsg)) || JSON.stringify(data))
      );
    }

    await wait(1000);
    await this.userInfoApi("after");
    if (this.coinBefore != null && this.coinAfter != null) {
      const delta = this.coinAfter - this.coinBefore;
      if (delta > 0) {
        log("✅ 账号[" + this.index + "] 金币已入账 +" + delta);
      } else if (delta === 0) {
        if (reportOk) {
          log(
            "⚠️ 账号[" +
              this.index +
              "] report 有 data 但金币 Δ=0。常见原因：今日已领过 / 触发失败 / 服务端延迟"
          );
        } else {
          log("账号[" + this.index + "] 金币无变化(Δ=0)");
        }
      } else {
        log("账号[" + this.index + "] 金币变化 " + delta);
      }
    }
    log(
      "账号[" +
        this.index +
        "] 完成 | trigger=" +
        (triggered ? "ok" : "fail") +
        " report=" +
        (reportOk ? "ok" : "fail")
    );
  }
}

async function main() {
  console.log(
    JSON.stringify(
      [
        "【快手极速版-仅每日签到】",
        "流程: 任务列表 -> trigger action -> signIn/report -> 核对金币",
        "ksck / ksTaskNum / ksAccountDelay",
      ],
      null,
      2
    )
  );

  const accounts = parseAccounts(process.env.ksck || process.env.KSCK || "");
  if (!accounts.length) {
    log("❌ 未找到环境变量 ksck");
    return;
  }

  let conc = parseInt(process.env.ksTaskNum || "1", 10);
  if (!conc || conc < 1) conc = 1;
  if (conc > 10) conc = 10;

  const delayEnv = process.env.ksAccountDelay;
  const delayDesc =
    delayEnv == null || String(delayEnv).trim() === ""
      ? "默认 60-120 秒随机"
      : String(delayEnv).trim() === "0"
        ? "关闭"
        : String(delayEnv);

  log("账号数: " + accounts.length + "  任务: signin  并发: " + conc + "  间隔: " + delayDesc);

  for (let i = 0; i < accounts.length; i += conc) {
    const batch = accounts.slice(i, i + conc);
    log("\n🚀 批次 " + (Math.floor(i / conc) + 1) + "，" + batch.length + " 个账号");

    if (conc === 1) {
      try {
        await new KsSignAccount(batch[0], i).run();
      } catch (e) {
        log("账号[" + (i + 1) + "] 崩溃: " + e.message);
      }
      if (i + 1 < accounts.length) {
        const ms = parseAccountDelayMs(delayEnv);
        if (ms > 0) {
          log(
            "⏳ 账号[" +
              (i + 1) +
              "] 完成，等待 " +
              formatDuration(ms) +
              " 后执行账号[" +
              (i + 2) +
              "] ..."
          );
          await wait(ms);
        }
      }
    } else {
      await Promise.all(
        batch.map((acc, j) =>
          new KsSignAccount(acc, i + j)
            .run()
            .catch((e) => log("账号[" + (i + j + 1) + "] 崩溃: " + e.message))
        )
      );
      if (i + conc < accounts.length) {
        const ms = parseAccountDelayMs(delayEnv);
        if (ms > 0) {
          log("⏳ 本批次完成，等待 " + formatDuration(ms) + " 后执行下一批 ...");
          await wait(ms);
        }
      }
    }
  }

  log("\n全部签到结束");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
