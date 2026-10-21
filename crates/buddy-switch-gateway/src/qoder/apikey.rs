//! Qoder 网关的多 API Key 存储（`sk-qoder-` 前缀 + **归属区域** + 三态动作）。
//!
//! 与 Trae 侧（`trae/apikey.rs`）**同款结构**：明文不落库、只存 `sha256`；
//! `prefix` / `suffix` 供脱敏展示（`prefix••••••••suffix`，**不含省略号**）；三态动作
//! **吊销 → 恢复 → 删除**，且**已吊销的行必须同时给「恢复 + 删除」两个出口**
//! （两平台同形的产品纪律 —— 只给删除会让「误吊销」只能靠删号重来）。
//!
//! ## 前缀为什么是 `sk-qoder-`（2026-10-17 改）
//!
//! 四条产品线的 Key 前缀是**同一族**，看一眼就知道该配哪个地址：
//! `sk-wb-`（WorkBuddy）· `sk-trae-`（Trae）· **`sk-qoder-`（Qoder）** · `sk-uni-`（统一网关）。
//! 原先 Qoder 用短前缀 `qd-`，与另外三条不成族——用户手里一把 `qd-…` 的 Key
//! 无从判断它属于哪个网关，AI 工具的「按前缀认提供商」规则也匹配不上。
//!
//! ⚠️ **兼容**：校验只比对 `sha256(完整明文)`，**不看前缀** ⇒ 老 `qd-…` Key
//! 升级后照常可用（改名前创建的记录原样留在磁盘上）；只有**新创建**的 Key 用新前缀。
//!
//! ## 与 Trae 侧的**两处刻意差异**
//!
//! 1. **绑定 `region` 而不是程序位**：Qoder 没有程序位轴（一个区域一本账号库、一套端点），
//!    网关按区域选池 ⇒ Key 归属就是区域。
//! 2. **没有 legacy 回落**：Qoder 网关是新增产品线，不存在「设置里的旧 apiKey」可迁 ——
//!    不照搬 Trae 的 `settings.api_key` 合成回落（那会把别人的历史包袱搬进来）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::apikey::constant_time_eq;
use buddy_switch_core::modules::qoder::region::QoderRegion;

/// 新 Key 的前缀字面量（创建时 `sk-qoder-<secret 前 4 位>`）。
///
/// 与 `sk-wb-` / `sk-trae-` / `sk-uni-` 同族；改这里只影响**新建**的 Key。
pub const KEY_PREFIX: &str = "sk-qoder-";

/// 明文 Key 的密钥段长度（32 位十六进制，与另三条产品线一致）。
const SECRET_HEX_LEN: usize = 32;

/// 区域 ↔ 字符串（磁盘 / 线上形状 `"cn"` / `"global"`；与 `QoderRegion::as_str` 一致）。
fn region_as_str<S: serde::Serializer>(
    region: &QoderRegion,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(region.as_str())
}

fn region_from_str<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<QoderRegion, D::Error> {
    let raw = String::deserialize(deserializer)?;
    Ok(QoderRegion::parse(&raw).unwrap_or_default())
}

/// 单条 Qoder API Key（明文不落库）。**含归属区域**。
///
/// 磁盘 / 线上形状为 camelCase（`createdAt` / `revokedAt` / `lastUsedAt`），
/// 前端类型逐字对齐。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QoderApiKeyRecord {
    pub id: String,
    pub name: String,
    /// 归属区域；缺省 = [`QoderRegion::default`]（国内版）。
    #[serde(
        default,
        serialize_with = "region_as_str",
        deserialize_with = "region_from_str"
    )]
    pub region: QoderRegion,
    /// 前缀（脱敏展示用），如 `sk-qoder-a1b2`。⚠️ **不含省略号**。
    pub prefix: String,
    /// 尾部 4 位（如 `9f3c`）。列表显示 `prefix••••••••suffix`。
    #[serde(default)]
    pub suffix: String,
    /// `sha256(hex)` of 完整明文 Key。
    pub hash: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

impl QoderApiKeyRecord {
    /// 脱敏展示（**不含 hash**，可安全下发到前端）。
    pub fn masked(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "region": self.region.as_str(),
            "prefix": self.prefix,
            "suffix": self.suffix,
            "createdAt": self.created_at,
            "revokedAt": self.revoked_at,
            "revoked": self.revoked_at.is_some(),
            "lastUsedAt": self.last_used_at,
        })
    }

    /// 是否已吊销。
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// `sha256` 十六进制小写。
fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn random_id() -> String {
    // 新 Key 的 id 与 secret 都来自 UUID（v4）：id 不泄密，secret 是 32 位十六进制。
    uuid::Uuid::new_v4().simple().to_string()
}

/// 读写 `qoder/gateway_keys.json` 的多 Key 存储。
///
/// **无进程内缓存**：每次操作都读盘 —— 独立监听与宿主路由两份实例创建即可见、
/// 吊销即时生效（与 Trae / WB 侧同一纪律）。
pub struct QoderApiKeyStore {
    path: PathBuf,
}

impl QoderApiKeyStore {
    /// 新建存储（不读取文件；每次操作实时读盘）。
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// 存储文件路径（供诊断/展示）。
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// 读取 Key 列表（文件缺失 / 损坏 ⇒ 空表）。
    pub fn load(&self) -> Vec<QoderApiKeyRecord> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str::<Vec<QoderApiKeyRecord>>(&text).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    fn save(&self, records: &[QoderApiKeyRecord]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let text = serde_json::to_string_pretty(records).map_err(|error| error.to_string())?;
        buddy_switch_core::modules::config::atomic_write(&self.path, &text)
            .map_err(|error| error.to_string())
    }

    /// 创建一把新 Key：返回 `(记录, 明文)` —— **明文只在这一刻出现一次**。
    pub fn create(
        &self,
        name: String,
        region: QoderRegion,
    ) -> Result<(QoderApiKeyRecord, String), String> {
        // 明文形态与另三条产品线逐字同族：`sk-qoder-` + 32 位 hex。
        let secret = format!("{KEY_PREFIX}{}", &random_id()[..SECRET_HEX_LEN]);
        let record = QoderApiKeyRecord {
            id: random_id(),
            name: if name.trim().is_empty() {
                "未命名 Key".to_string()
            } else {
                name.trim().to_string()
            },
            region,
            prefix: format!(
                "{KEY_PREFIX}{}",
                &secret[KEY_PREFIX.len()..KEY_PREFIX.len() + 4]
            ),
            suffix: secret.chars().skip(secret.chars().count() - 4).collect(),
            hash: sha256_hex(&secret),
            created_at: now_ms(),
            revoked_at: None,
            last_used_at: None,
        };
        let mut records = self.load();
        records.push(record.clone());
        self.save(&records)?;
        Ok((record, secret))
    }

    /// 校验一把明文 Key：命中且未吊销 ⇒ 记录，并**顺手 touch** `lastUsedAt`。
    ///
    /// ★ **常量时间比较**（规格 D4）：命中的判据走 [`constant_time_eq`]，**不**用
    /// `record.hash == hash`。`String` 的 `==` 在首个不同字节处就返回，比较耗时随
    /// 「共同前缀长度」线性变化；键校验是网关的安全边界，没有理由留一条「只差写法」的
    /// 时序侧信道。哈希是 64 位小写 hex（恒等长），长度不同由 [`constant_time_eq`] 判否。
    ///
    /// ⚠️ 遍历**不提前 break**：提前退出会把「命中第几条记录」写进耗时。
    pub fn verify(&self, presented: &str) -> Option<QoderApiKeyRecord> {
        let trimmed = presented.trim();
        if trimmed.is_empty() {
            return None;
        }
        let hash = sha256_hex(trimmed);
        let records = self.load();
        let mut matched: Option<&QoderApiKeyRecord> = None;
        for record in &records {
            if constant_time_eq(record.hash.as_bytes(), hash.as_bytes()) && !record.is_revoked() {
                matched = Some(record);
            }
        }
        let record = matched?;
        self.touch(&record.id);
        Some(record.clone())
    }

    /// 记录一次使用（写盘失败**忽略** —— 使用时间戳是统计信息，不能阻断请求）。
    pub fn touch(&self, id: &str) {
        let mut records = self.load();
        if let Some(record) = records.iter_mut().find(|record| record.id == id) {
            record.last_used_at = Some(now_ms());
            let _ = self.save(&records);
        }
    }

    /// 吊销（置 `revoked_at`；已吊销 ⇒ 可读错误）。
    pub fn revoke(&self, id: &str) -> Result<(), String> {
        let mut records = self.load();
        let record = records
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "找不到该 Key".to_string())?;
        if record.is_revoked() {
            return Err("该 Key 已是吊销状态".to_string());
        }
        record.revoked_at = Some(now_ms());
        self.save(&records)
    }

    /// 恢复吊销（清 `revoked_at`；未吊销 ⇒ 可读错误）。
    pub fn restore(&self, id: &str) -> Result<(), String> {
        let mut records = self.load();
        let record = records
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or_else(|| "找不到该 Key".to_string())?;
        if !record.is_revoked() {
            return Err("该 Key 未被吊销，无需恢复".to_string());
        }
        record.revoked_at = None;
        self.save(&records)
    }

    /// 删除（**仅已吊销可删** —— 未吊销必须先吊销，防误删在用凭据）。
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let records = self.load();
        let record = records
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| "找不到该 Key".to_string())?;
        if !record.is_revoked() {
            return Err("只能删除已吊销的 Key：请先吊销，再删除".to_string());
        }
        let remaining: Vec<QoderApiKeyRecord> = records
            .into_iter()
            .filter(|record| record.id != id)
            .collect();
        self.save(&remaining)
    }

    /// 列表（脱敏）。
    pub fn list(&self) -> Vec<Value> {
        self.load().iter().map(QoderApiKeyRecord::masked).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (QoderApiKeyStore, PathBuf) {
        let path = std::env::temp_dir().join(format!("qoder-keys-test-{}.json", random_id()));
        (QoderApiKeyStore::new(path.clone()), path)
    }

    /// 三态动作的合同：吊销 → 恢复 → 删除；未吊销不可删；记录里**永远没有明文**。
    ///
    /// 变异：把 `delete` 的「仅已吊销可删」守卫删掉 ⇒ 本测试红。
    #[test]
    fn key_lifecycle_three_states_and_no_plaintext_on_disk() {
        let (store, path) = temp_store();
        let (record, secret) = store.create("测试".into(), QoderRegion::Cn).unwrap();
        assert!(secret.starts_with(KEY_PREFIX), "{secret}");
        assert!(record.prefix.starts_with(KEY_PREFIX));

        // 明文**不落盘**：磁盘文件里不得出现 secret 本体。
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains(&secret), "磁盘出现明文 Key");

        // 校验通过 + touch 生效。
        assert!(store.verify(&secret).is_some());
        assert!(store.load()[0].last_used_at.is_some());

        // 未吊销不可删。
        assert!(store.delete(&record.id).is_err());
        // 吊销（幂等保护）→ 校验失败。
        store.revoke(&record.id).unwrap();
        assert!(store.revoke(&record.id).is_err());
        assert!(store.verify(&secret).is_none(), "吊销后必须拒绝");
        // 恢复 → 又能用。
        store.restore(&record.id).unwrap();
        assert!(store.verify(&secret).is_some());
        assert!(store.restore(&record.id).is_err(), "未吊销无需恢复");
        // 吊销 → 删除。
        store.revoke(&record.id).unwrap();
        store.delete(&record.id).unwrap();
        assert!(store.load().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn masked_never_contains_hash_or_secret() {
        let (store, path) = temp_store();
        let (_record, secret) = store.create("m".into(), QoderRegion::Global).unwrap();
        let list = store.list();
        let text = serde_json::to_string(&list).unwrap();
        assert!(!text.contains(&secret));
        assert!(!text.contains("hash"), "脱敏列表不得带 hash 字段");
        assert_eq!(list[0]["region"], "global");
        assert!(list[0]["prefix"].as_str().unwrap().starts_with(KEY_PREFIX));
        let _ = std::fs::remove_file(&path);
    }

    /// 明文形态与另三条产品线**同族**：`sk-qoder-` + 32 位 hex。
    ///
    /// 变异：把 `KEY_PREFIX` 改回 `qd-`，或把 hex 段长度改回 28 ⇒ 本条红。
    #[test]
    fn plaintext_shape_matches_the_other_product_lines() {
        let (store, path) = temp_store();
        let (record, secret) = store.create("shape".into(), QoderRegion::Cn).unwrap();
        assert!(
            secret.starts_with("sk-qoder-"),
            "前缀应为 sk-qoder-：{secret}"
        );
        assert_eq!(
            secret.len(),
            "sk-qoder-".len() + SECRET_HEX_LEN,
            "明文长度应为前缀 + 32 位 hex：{secret}"
        );
        let hex = &secret["sk-qoder-".len()..];
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "密钥段必须是十六进制：{hex}"
        );
        assert_eq!(
            record.prefix,
            format!("sk-qoder-{}", &hex[..4]),
            "展示前缀 = 前缀 + 密钥段前 4 位"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 改前缀**不废老 Key**：校验只比 `sha256(完整明文)`、不看前缀
    /// ⇒ 磁盘上既有的 `qd-…` 记录升级后照常通过。
    #[test]
    fn legacy_qd_keys_still_verify_after_the_prefix_change() {
        let (store, path) = temp_store();
        let legacy = "qd-0123456789abcdef0123456789abcd";
        let record = QoderApiKeyRecord {
            id: "legacy-1".to_string(),
            name: "老 Key".to_string(),
            region: QoderRegion::Cn,
            prefix: "qd-0123".to_string(),
            suffix: "abcd".to_string(),
            hash: sha256_hex(legacy),
            created_at: 0,
            revoked_at: None,
            last_used_at: None,
        };
        let text = serde_json::to_string_pretty(&vec![record]).unwrap();
        std::fs::write(&path, text).unwrap();

        assert!(store.verify(legacy).is_some(), "老的 qd- Key 必须继续可用");
        assert!(store
            .verify("qd-ffffffffffffffffffffffffffffffff")
            .is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// 校验必须是**常量时间比较**（规格 D4）。
    ///
    /// 行为面：只差最后一个字符 / 长度不同 / 空串都必须判否，正确明文必须判是。
    /// 结构面：本仓没有给 `constant_time_eq` 打桩的手段，所以另加一条源码级断言 ——
    /// `verify` 的实现里**不得再出现** `record.hash ==` 这种短路径比较
    /// （变异：把实现改回 `==` ⇒ 本条红）。
    #[test]
    fn verify_compares_in_constant_time_and_rejects_near_misses() {
        let (store, path) = temp_store();
        let (record, secret) = store.create("ct".into(), QoderRegion::Cn).unwrap();

        // 正确明文 ⇒ 命中同一条记录。
        let hit = store.verify(&secret).expect("正确明文必须通过");
        assert_eq!(hit.id, record.id);

        // 等长但末位不同（近失配）⇒ 否。
        let mut near_miss = secret.clone().into_bytes();
        let last = near_miss.len() - 1;
        near_miss[last] = if near_miss[last] == b'0' { b'1' } else { b'0' };
        let near_miss = String::from_utf8(near_miss).unwrap();
        assert!(
            store.verify(&near_miss).is_none(),
            "末位不同的 Key 必须被拒"
        );

        // 长度不同 ⇒ 否（`constant_time_eq` 的长度分支）。
        assert!(store.verify(&secret[..secret.len() - 1]).is_none());
        assert!(store.verify("").is_none());
        assert!(store.verify("   ").is_none());

        // 首尾空白被 trim（既有契约），不得因 trim 丢掉命中。
        assert!(store.verify(&format!("  {secret}  ")).is_some());

        let _ = std::fs::remove_file(&path);

        let source = include_str!("apikey.rs");
        let verify_body = source
            .split("pub fn verify(&self, presented: &str)")
            .nth(1)
            .expect("找不到 verify 实现");
        let verify_body = &verify_body[..verify_body
            .find("pub fn touch")
            .unwrap_or(verify_body.len())];
        assert!(
            verify_body.contains("constant_time_eq"),
            "verify 必须走 constant_time_eq"
        );
        assert!(
            !verify_body.contains("record.hash ==") && !verify_body.contains(".hash == hash"),
            "verify 不得回退到短路径字符串比较（D4）"
        );
    }
}
