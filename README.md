# Verifiable-Editable-Lightweight-Blockchain
轻量化存储的可验证可编辑区块链框架研究
# 🔐 可编辑区块链变色龙哈希研究框架

一个轻量化、可编辑、可验证的区块链研究框架，集成了策略变色龙哈希（PCH）、CP-ABE属性基加密、MPC多方计算共识等先进密码学技术。

## 🌟 核心特性

### 1. **策略变色龙哈希（Policy Chameleon Hash, PCH）**
   - 基于增强版CP-ABE实现细粒度访问控制
   - 支持复杂策略：`(attr0 and attr1) or (threshold(2, attr2, attr3, attr4))`
   - 满足策略的用户可生成哈希碰撞，实现合法编辑

### 2. **多层密码学架构**
   - **双层变色龙哈希**：分离CA与委员会密钥，明确ROM假设
   - **轻量RHVT**：基于强RSA假设的向量聚合认证
   - **区块链认证树（BAT）**：高效范围查询和完整性验证

### 3. **MPC共识机制**
   - 基于Shamir秘密共享的编辑决策
   - 拜占庭容错：阈值 t = 2n/3 + 1
   - 可配置网络可靠性模型

### 4. **研究友好设计**
   - 模块化架构，便于扩展
   - 完整的性能评估体系
   - 交互式演示与自动化测试套件

## 📁 项目结构
├── blockchain.py # 区块链核心实现
├── test_blockchain.py # 交互式演示与测试工具
├── requirements.txt # Python依赖包配置
├── README.md # 项目说明文档


## 本框架支持以下研究方向：

理论验证
随机预言机模型（ROM）假设的明确声明与验证

强RSA假设下的RHVT安全性证明（需进一步修改实现）

策略隐藏性与不可区分性实验设计

性能分析
存储效率对比：RHVT vs 传统Merkle树

编辑延迟分析：普通区块 vs PCH策略区块

策略复杂度影响：不同策略深度对性能的影响

安全特性
前向安全性：委员会密钥轮换机制

抗合谋攻击：基于MSP的属性基加密

可验证性：BAT树支持高效范围查询证明
## 🚀 快速开始

### 环境要求
- Python 3.8+
- 推荐：虚拟环境（venv或conda）

### 安装依赖

# 安装核心依赖
pip install -r requirements.txt

# 可选：安装开发工具
pip install -r requirements.txt[dev]

# 可选：安装分析工具
pip install -r requirements.txt[analysis]
## 运行交互式演示
python test_blockchain.py

⚠️ 重要说明
安全性警告
研究框架：本实现主要用于密码学研究验证

非生产级：未经过严格的安全审计，不建议用于生产环境

简化实现：CP-ABE使用PBKDF2+AES模拟，非标准双线性配对

性能考虑
演示模式使用1024位RSA密钥以提高速度

生产环境建议使用2048位以上密钥

大规模部署需要考虑内存和计算优化
## 特别说明
目前项目属于研究测试阶段，实现尚不完善，还需进行进一步改进


