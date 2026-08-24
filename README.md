# Still Alive
> *此项目尚在开发中，还未进行测试。*

> **有些东西，希望最后确实交到那个人手里。**

Still Alive 是一个私有、自托管的**定向数字内容交付系统**。

你可以为不同的人准备不同的文件、信件、照片、存档或其他数字内容。访问者不需要预先拥有账号，也不需要从一张收件人列表里选择自己的名字。

系统会像一个小型的“网络天才”一样，通过一系列关于你们之间关系与共同经历的问题，逐渐判断访问者是谁。

当身份足够明确后，Still Alive 会提出一个属于这个人的最终验证问题。

验证成功后，系统才会交付为他准备的内容。

```text
回答问题
   ↓
逐渐识别身份
   ↓
“我想我知道你是谁了。”
   ↓
确认身份
   ↓
回答专属验证问题
   ↓
领取属于你的内容
```

它不是一个公共网盘，也不是传统意义上的账号系统。

Still Alive 更关心的是另一件事：

> **一个人是否真的拥有与你共同经历过那段历史。**

---

## 为什么会有这个项目

现实中的朋友关系并不总能被手机号、邮箱或真实姓名准确描述。

有些人可能只存在于：

* 某个游戏好友列表；
* Discord 或其他社区；
* 很久以前的项目；
* 一段共同经历；
* 一个已经没人使用的聊天群；
* 只有你们两个人还记得的事情里。

他们之间甚至可能互相不知道对方的存在。

但你仍然可能有一些东西，希望将来只交给其中某一个人。

Still Alive 因此把整个流程拆成四个独立阶段：

```text
Discovery
找到“你可能是谁”

Confirmation
确认系统猜测的身份

Verification
证明你确实掌握属于这段关系的共同记忆

Delivery
交付只属于这个身份的内容
```

**识别成功并不等于获得内容权限。**

即使 Discovery 猜错了人物，也必须通过该人物独立的 Verification，才能产生真正的下载授权。

---

## Identity Discovery

Still Alive 不使用固定的巨大 `if / else` 问答树。

人物拥有自己的特征与答案，Identity Engine 根据当前候选人的分布动态决定下一道最有价值的问题。

例如：

```text
我们在线下见过吗？

[ 是 ]
[ 大概是 ]
[ 不确定 ]
[ 大概不是 ]
[ 不是 ]
```

每次回答都会重新更新候选人的得分。

问题选择同时考虑：

* 信息增益；
* 当前候选人的可区分度；
* 问题隐私等级；
* 已经询问过的问题；
* 模糊回答带来的不确定性。

因此新增人物通常不需要重新设计整套问答流程。

---

## Identity Integrity

朋友越来越多以后，最麻烦的问题不是“题目太多”，而是：

> **两个人太像了。**

Still Alive 会在后台自动寻找可能得到相近识别结果的人物。

例如：

```text
Alice ↔ Bob

模拟混淆率     4.7%
最终得分差距   0.062

状态：BLOCKING
```

管理员可以进入 Identity Integrity Wizard，查看两个人为什么难以区分，并补充新的差异问题。

```text
发现冲突
   ↓
增加一个能区分他们的问题
   ↓
填写双方答案
   ↓
重新模拟
   ↓
仍然相似？
   ├─ 是 → 继续补充
   └─ 否 → 解决下一组
```

Still Alive 会持续进行 Pair / Cluster 分析，而不是要求管理员自己记住几十个人之间所有可能的组合。

对于无法安全区分的人物，公共识别流程宁可返回：

> **我现在还不能确定你是谁。**

也不会为了完成游戏流程强行猜测。

---

## Verification

Identity Discovery 只是候选身份判断。

真正的授权发生在 Verification。

每个人可以拥有独立的验证问题，例如：

```text
我们第一次一起玩的那个游戏叫什么？
```

验证答案不会以明文形式保存在数据库中。

Still Alive 对验证数据使用服务端秘密参与的摘要机制，并对在线验证进行限速与失败控制。

验证成功后，系统才会产生短期、受限的 Download Grant。

---

## Encrypted Vault

需要交付的文件不会直接以明文形式存放在公开目录中。

Still Alive 使用独立的数据加密密钥保护 Vault 中的内容，并通过 Envelope Encryption 管理文件密钥。

```text
Master Key
    │
    ├── Asset DEK ── encrypted file
    ├── Asset DEK ── encrypted file
    └── Asset DEK ── encrypted file
```

数据库、Vault 与 Master Key 被视为不同的安全边界。

即使数据库和文件目录被单独取得，也不应该因此直接暴露内容明文。

---

## Verified Download Grant

验证成功后不会直接暴露真实文件路径。

服务器会创建一个临时 Download Grant：

```text
Verification Passed
        ↓
short-lived grant
        ↓
/download/<random-token>
        ↓
encrypted asset
        ↓
authorized delivery
```

Grant 可以限制：

* 对应人物；
* 对应内容；
* 有效时间；
* 最大下载次数；
* 所属验证 Session。

不同人物之间的内容授权相互隔离。

---

## Sealed Release

Still Alive 还支持生成 **Sealed Release**。

它的目的不是控制“什么时候允许别人访问”，而是冻结一个能够长期保存和恢复的完整版本。

封存版本用于保存：

* 当前应用；
* 数据库快照；
* 加密 Vault；
* 所需运行依赖；
* 完整性校验信息；
* 恢复脚本；
* 离线运行说明。

目标是：

> **即使原开发环境、Git 仓库或在线依赖已经不存在，仅凭封存包和必要密钥材料，仍然能够重新启动 Still Alive。**

当前版本的内容在部署完成后立即可用。

Still Alive **目前不实现 Heartbeat、Dead Man's Switch、所有者存活检测或倒计时触发机制**。这些能力如果未来加入，也会作为独立的 Lifecycle 模块存在，而不会改变当前的即时交付模式。

---

# 部署

## 环境要求

推荐：

* Python 3.12
* Windows / Linux
* SQLite
* Python virtual environment

克隆项目并准备虚拟环境后，在项目根目录创建 `.env`。

配置项清单与部署参数属于内部规范，不随公开仓库发布。`MASTER_KEY` 必须使用真正随机生成的 **32 字节密钥**并进行 Base64 编码。

不要直接使用示例中的 secret。

---

## Windows

安装依赖：

```powershell
.\.venv\Scripts\pip.exe install -e ".[dev]"
```

初始化 / 更新数据库：

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

启动：

```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --reload
```

或者：

```powershell
.\scripts\start.ps1
```

`start.ps1` 会自动执行数据库 migration 后启动服务。

如果需要修改端口：

```powershell
$env:STILL_ALIVE_PORT="8080"
.\scripts\start.ps1
```

默认地址：

```text
http://127.0.0.1:8000/
```

健康检查：

```text
GET /health/live
GET /health/ready
```

---

# 测试

运行完整 Python 测试：

```powershell
.\.venv\Scripts\pytest.exe
```

## Browser E2E

真实浏览器验收默认不会自动执行。

启用 Playwright Chromium 流程：

```powershell
$env:RUN_E2E="1"

.\.venv\Scripts\python.exe -m pytest -q tests/test_e2e_browser.py -m e2e
```

这些测试覆盖包括：

```text
后台创建人物
→ 配置识别题
→ Identity Integrity 检查
→ Public Discovery
→ Confirmation
→ Verification
→ Verified Download
```

## OCI / Offline Recovery

严格封存版本和离线恢复测试需要 Docker 环境。

在支持 Docker 的 Linux CI Runner 中设置：

```text
RUN_OCI=1
```

后执行对应测试。

---

# Recovery Key

管理员可以在后台配置独立的 Recovery Key，用于 Sealed Release 的离线恢复。

Recovery Key：

* 不写入数据库；
* 不写入日志；
* 不包含在 Sealed Release 中；
* 不应与 Master Key 存放在同一个位置。

创建严格封存版本时，Still Alive 可以生成：

* hash wheelhouse；
* OCI image tar；
* 数据库与 Vault 快照；
* `README-FIRST.txt`；
* `scripts/restore-oci.sh`；
* `scripts/restore-linux.sh`。

恢复人员不应该需要理解整个 Still Alive 源码才能完成恢复。

---

# 安全原则

Still Alive 处理的可能是非常私人的关系数据和数字内容，因此项目默认采用较严格的安全边界。

请至少遵守：

**不要提交到 Git：**

```text
.env
data/
Master Key
Recovery Key
运行环境 Secrets
未加密的私人内容
```

**Public Client 不应该获得：**

```text
完整人物列表
其他人物答案
候选人真实概率
验证答案
Vault 文件路径
加密密钥
管理员信息
```

浏览器只获得完成当前交互所必需的数据。

---

# 项目状态

Still Alive 目前已经能够完成完整的：

```text
Admin Authoring
      ↓
Identity Integrity
      ↓
Public Discovery
      ↓
Verification
      ↓
Encrypted Delivery
      ↓
Sealed Recovery
```

详细工程状态、验收结果、当前已知限制和工程规范属于内部资料，不随公开仓库发布。

---

# 这不是什么

Still Alive **不是法律意义上的遗嘱工具**。

它不负责确定：

* 法定继承人；
* 财产权属；
* 遗产分割；
* 法律身份；
* 法律意义上的死亡认定。

它只是一个数字内容识别、验证与交付系统。

如果内容涉及真正的资产继承、账号所有权、金融资产或其他法律事项，应当使用对应司法管辖区认可的正式法律安排。

---

# Still Alive

只要服务器还能够运行，只要那段共同记忆还存在，

它就还有机会认出那个应该收到这些东西的人。
