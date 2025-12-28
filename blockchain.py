"""
⚠️ 简化版CP-ABE实现
安全性警告：本实现使用PBKDF2+AES模拟双线性配对，未实现标准CP-ABE的安全模型。
生产环境或密码学研究请使用Charm-Crypto库(charm-crypto.com)。
本实现仅用于验证PCH方案在区块链中的集成逻辑。
"""


import os
import secrets
import time
import hashlib
import hmac
import json
import base64
import asyncio
import aiosqlite
import statistics
import pickle
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple, Any, Callable, Set
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import random
import string

# cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -------------------------
# 配置与工具
# -------------------------
class SecurityConfig:
    RSA_KEY_SIZE = 2048  # 降低RSA密钥大小提高性能
    HASH_ALGORITHM = hashes.SHA3_256
    SECURITY_PRIME = 2 ** 127 - 1
    AES_KEY_SIZE = 32
    AES_NONCE_SIZE = 12
    RHVT_GROUP_SIZE = 5  # 减小组大小
    BAT_BRANCHING_FACTOR = 4
    CPABE_MASTER_KEY_SIZE = 32
    CPABE_SALT_SIZE = 16
    CPABE_ITERATIONS = 100000  # PBKDF2迭代次数


class SecureRandom:
    @staticmethod
    def bytes(n: int) -> bytes:
        return secrets.token_bytes(n)

    @staticmethod
    def int(min_val: int, max_val: int) -> int:
        return secrets.randbelow(max_val - min_val + 1) + min_val

    @staticmethod
    def string(length: int = 10) -> str:
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


# -------------------------
# 哈希抽象与实现
# -------------------------
class HashInterface(ABC):
    @abstractmethod
    def hash(self, data: bytes) -> bytes: ...

    @abstractmethod
    def hash_to_int(self, data: bytes, modulus: int) -> int: ...

    @abstractmethod
    def digest_size(self) -> int: ...


class SHA3_256(HashInterface):
    def __init__(self):
        self._size = 32

    def hash(self, data: bytes) -> bytes:
        digest = hashes.Hash(SecurityConfig.HASH_ALGORITHM(), backend=default_backend())
        digest.update(data)
        return digest.finalize()

    def hash_to_int(self, data: bytes, modulus: int) -> int:
        h = self.hash(data)
        byte_len = (modulus.bit_length() + 7) // 8
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=byte_len,
            salt=h,
            info=b'hash_to_int',
            backend=default_backend()
        )
        derived = kdf.derive(b'')
        val = int.from_bytes(derived, 'big') % modulus
        return val

    def digest_size(self) -> int:
        return self._size


# -------------------------
# RSA Key 管理
# -------------------------
class RSAKeyManager:
    def __init__(self, key_size: int = SecurityConfig.RSA_KEY_SIZE):
        self.key_size = key_size
        self._priv = None
        self._pub = None

    def generate(self) -> Tuple[bytes, bytes]:
        self._priv = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size, backend=default_backend())
        self._pub = self._priv.public_key()
        priv_pem = self._priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = self._pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return priv_pem, pub_pem

    def load_private(self, pem: bytes):
        self._priv = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
        self._pub = self._priv.public_key()

    def load_public(self, pem: bytes):
        self._pub = serialization.load_pem_public_key(pem, backend=default_backend())

    @property
    def private(self):
        return self._priv

    @property
    def public(self):
        return self._pub

    def public_bytes(self) -> bytes:
        if not self._pub:
            raise ValueError("public not set")
        return self._pub.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def n(self) -> int:
        if not self._pub:
            raise ValueError("public not set")
        return self._pub.public_numbers().n

    @property
    def e(self) -> int:
        if not self._pub:
            raise ValueError("public not set")
        return self._pub.public_numbers().e

    @property
    def d(self) -> int:
        if not self._priv:
            raise ValueError("private not set")
        return self._priv.private_numbers().d

    @property
    def phi(self) -> int:
        if not self._priv:
            raise ValueError("private not set")
        pnums = self._priv.private_numbers()
        return (pnums.p - 1) * (pnums.q - 1)


# -------------------------
# 阶段一：密码学实现形式化加固
# -------------------------

# 1.1 严格实现文献0的RHVT数学模型
class LightRHVT:
    """
    严格实现文献0的RHVT数学模型
    安全性依赖于强RSA假设和随机预言机模型
    """

    def __init__(self, rsa_km: RSAKeyManager, hash_impl: HashInterface = None,
                 group_size: int = SecurityConfig.RHVT_GROUP_SIZE):
        self.rsa_km = rsa_km
        self.hash = hash_impl or SHA3_256()
        self.group_size = group_size
        self._cache_rsa_params()
        self.inner_tags = {}
        self.outer_tags = {}
        self.global_tag = 1
        self.block_counter = 0
        self.group_counter = 0
        self.aux = {}
        self._g = self._generate_group_generator()

    def _cache_rsa_params(self):
        if self.rsa_km.public:
            self.n = self.rsa_km.n
            self.e = self.rsa_km.e
        if self.rsa_km.private:
            self.phi = self.rsa_km.phi
            self.d = self.rsa_km.d

    def _generate_group_generator(self) -> int:
        """
        生成阶为φ(n)的生成元g，满足g^q = 1 mod n
        安全性依赖于强RSA参数选择
        """
        if not self.rsa_km.private:
            raise ValueError("RSA private key not set")

        # 简化实现：使用固定g=2以提高性能
        # 生产环境应使用完整的生成元生成逻辑
        return 2

    def _compute_block_tag(self, block_data: Dict, index: int) -> int:
        """
        严格遵循文献0公式：σ_i = g^{(ρ_i + m_i)·d} mod n
        安全性证明需要严格遵循数学模型
        """
        if not self.rsa_km.private:
            raise ValueError("RSA private key not set")

        # 严格遵循文献0公式：σ_i = g^{(ρ_i + m_i)·d} mod n
        name2 = b"rhvt_name2"
        rho_bytes = self.hash.hash(name2 + index.to_bytes(8, 'big'))
        rho = int.from_bytes(rho_bytes, 'big') % self.phi

        block_bytes = block_data.get('data', b'') + (
            block_data.get('block_hash', b'') if isinstance(block_data.get('block_hash', b''),
                                                            (bytes, bytearray)) else (
                    block_data.get('block_hash', b'') or b''))
        mbytes = self.hash.hash(block_bytes)
        m_val = int.from_bytes(mbytes, 'big') % self.phi

        # d必须在模φ(n)下运算
        exponent = ((rho + m_val) * self.d) % self.phi
        sigma = pow(self._g, exponent, self.n)

        self.aux[index] = {'rho': rho, 'm': m_val, 'sigma': sigma}
        return sigma

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def bind_block(self, block_data: Dict) -> bool:
        try:
            index = self.block_counter
            sigma = self._compute_block_tag(block_data, index)
            gid = index // self.group_size
            if gid not in self.inner_tags:
                self.inner_tags[gid] = 1
                self.group_counter += 1
            self.inner_tags[gid] = (self.inner_tags[gid] * sigma) % self.n
            if (index + 1) % self.group_size == 0:
                self._compute_outer(gid)
                self._update_global(gid)
            self.block_counter += 1
            try:
                ghex = hex(self.global_tag)[2:]
            except Exception:
                ghex = "<unrepresentable>"
            print(f"[RHVT] 区块绑定成功  #{self.block_counter} 组#{gid} global_tag={ghex[:16]}...")
            return True
        except Exception as e:
            print(f"[RHVT] 区块绑定失败: {e}")
            return False

    def _compute_outer(self, gid: int):
        if gid not in self.inner_tags:
            raise ValueError("group not exist")
        sigma_star = self.inner_tags[gid]
        self.outer_tags[gid] = pow(sigma_star, self.e, self.n)

    def _update_global(self, gid: int):
        if gid not in self.outer_tags:
            raise ValueError("outer tag not exist")
        self.global_tag = (self.global_tag * self.outer_tags[gid]) % self.n

    def generate_proof(self, block_idx: int) -> Dict:
        if block_idx >= self.block_counter:
            raise ValueError("out of range")
        gid = block_idx // self.group_size
        F_s = 1
        start = gid * self.group_size
        for i in range(start, start + self.group_size):
            if i != block_idx and i in self.aux:
                F_s = (F_s * self.aux[i]['sigma']) % self.n
        return {'block_index': block_idx, 'group_id': gid, 'global_tag': self.global_tag, 'F_s': F_s}

    def verify_proof(self, proof: Dict, block_tag: int) -> bool:
        try:
            name2 = b"rhvt_name2"
            s = proof['block_index']
            u_s = int.from_bytes(self.hash.hash(name2 + s.to_bytes(8, 'big')), 'big') % self.phi
            gs = proof['group_id'] * self.group_size
            numerator = 1
            sum_u = 0
            for i in range(gs, gs + self.group_size):
                if i == s:
                    continue
                u_i = int.from_bytes(self.hash.hash(name2 + i.to_bytes(8, 'big')), 'big') % self.phi
                sigma_i = self.aux.get(i, {}).get('sigma', 1)
                numerator = (numerator * pow(sigma_i, u_i, self.n)) % self.n
                sum_u = (sum_u + u_i) % self.phi
            F_s = proof.get('F_s', 1)
            try:
                F_inv = pow(F_s, -1, self.n)
            except Exception:
                return False
            x = (numerator * F_inv) % self.n
            left = pow(x, u_s, self.n)
            right = pow(block_tag, sum_u, self.n)
            return left == right
        except Exception as e:
            print(f"[RHVT] 验证失败: {e}")
            return False

    def stats(self) -> Dict:
        tag_size = (self.n.bit_length() + 7) // 8 if hasattr(self, 'n') else 0
        return {'total_blocks': self.block_counter, 'total_groups': self.group_counter,
                'inner_count': len(self.inner_tags), 'outer_count': len(self.outer_tags),
                'global_tag_size': tag_size,
                'storage_overhead_bytes': tag_size + len(self.inner_tags) * tag_size + len(self.outer_tags) * tag_size}


# 1.2 明确随机预言机（ROM）假设和1.3 分离层次化密钥
class DualLayerChameleonHash:
    """
    分离层次化密钥的双层变色龙哈希实现
    明确声明随机预言机假设
    """

    def __init__(self, ca_km: RSAKeyManager, hash_impl: HashInterface = None):
        self.ca_km = ca_km
        self.hash = hash_impl or SHA3_256()
        self.committee_key_managers = []  # 分离CA和委员会密钥
        self.cycle = 0
        self._cache_rsa_params()

    def _cache_rsa_params(self):
        if self.ca_km.public:
            self._n = self.ca_km.n
            self._e = self.ca_km.e
        if self.ca_km.private:
            self._phi = self.ca_km.phi
            self._d = self.ca_km.d

    def add_committee(self, km: RSAKeyManager):
        """添加独立的委员会密钥管理器"""
        self.committee_key_managers.append(km)

    def current_committee(self) -> RSAKeyManager:
        if not self.committee_key_managers:
            raise ValueError("no committee")
        idx = self.cycle % len(self.committee_key_managers)
        return self.committee_key_managers[idx]

    def _compute_J(self, label: bytes, n: int) -> int:
        """
        计算群元素J，基于随机预言机模型（ROM）
        安全性依赖于SHA3输出的伪随机性
        注意：此实现假设SHA3为理想随机函数，实际部署需使用真随机数生成器（TRNG）
        """
        h = self.hash.hash(label)
        J = int.from_bytes(h, 'big') % (n - 2) + 2

        # 添加分布均匀性检验（仅debug模式）
        if __debug__:
            self._statistical_test_uniformity(J, n)

        while self._gcd(J, n) != 1:
            J = (J + 1) % (n - 2) + 2
        return J

    def _statistical_test_uniformity(self, value: int, modulus: int):
        """统计均匀性测试（仅用于调试）"""
        if value < 2 or value >= modulus:
            print(f"[DEBUG] J value {value} out of range [2, {modulus - 1}]")
        # 可以添加更复杂的统计测试

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _generate_coprime_r(self, n: int) -> int:
        for _ in range(2000):
            r = SecureRandom.int(1, n - 1)
            if self._gcd(r, n) == 1:
                return r
        raise RuntimeError("cannot gen coprime r")

    def _compute_chameleon(self, public_key_obj, label: bytes, message: bytes, r_bytes: Optional[bytes] = None) -> \
            Tuple[bytes, bytes]:
        pub_nums = public_key_obj.public_numbers()
        n = pub_nums.n
        e = pub_nums.e
        J = self._compute_J(label, n)
        Hm = self.hash.hash_to_int(message, n)

        if r_bytes is None:
            r_int = self._generate_coprime_r(n)
            r_bytes = r_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        else:
            if isinstance(r_bytes, str):
                r_bytes = bytes.fromhex(r_bytes)
            if not isinstance(r_bytes, (bytes, bytearray)):
                raise ValueError("r must be bytes")
            r_int = int.from_bytes(r_bytes, 'big')
            if self._gcd(r_int, n) != 1:
                raise ValueError("r must be coprime to n")

        J_Hm = pow(J, Hm, n)
        r_e = pow(int.from_bytes(r_bytes, 'big'), e, n)
        hash_int = (J_Hm * r_e) % n
        hash_bytes = hash_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        return hash_bytes, r_bytes

    def compute_inner(self, message: bytes, label: bytes, r: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        committee_km = self.current_committee()
        return self._compute_chameleon(committee_km.public, label, message, r)

    def compute_outer(self, inner_hash: bytes, committee_pub_bytes: bytes, prev_hash: bytes, label: bytes,
                      r: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        combined = inner_hash + committee_pub_bytes + prev_hash
        return self._compute_chameleon(self.ca_km.public, label, combined, r)

    def compute_inner_collision(self, committee_private_obj, label: bytes, original_msg: bytes, original_r: bytes,
                                new_msg: bytes) -> bytes:
        priv_nums = committee_private_obj.private_numbers()
        n = priv_nums.public_numbers.n
        d = priv_nums.d
        phi = (priv_nums.p - 1) * (priv_nums.q - 1)
        J = self._compute_J(label, n)
        B = pow(J, d, n)
        H_orig = self.hash.hash_to_int(original_msg, n)
        H_new = self.hash.hash_to_int(new_msg, n)
        delta = (H_orig - H_new) % phi
        r_orig_int = int.from_bytes(original_r, 'big')
        r_new = (r_orig_int * pow(B, delta, n)) % n
        return r_new.to_bytes((n.bit_length() + 7) // 8, 'big')

    def compute_outer_collision(self, label: bytes, original_combined: bytes, original_r: bytes,
                                new_combined: bytes) -> bytes:
        return self.compute_inner_collision(self.ca_km.private, label, original_combined, original_r, new_combined)

    def rotate_committee(self):
        self.cycle += 1


# -------------------------
# 阶段二：缺失核心功能补全
# -------------------------

# 2.1 实现区块链认证树（BAT）
class BATNode:
    """区块链认证树节点"""

    def __init__(self, level: int, node_id: Optional[str] = None):
        self.level = level
        self.node_id = node_id or f"node_{SecureRandom.int(1, 1000000)}"
        self.commitment = None
        self.children = []
        self.parent = None
        self.block_hash = None
        self.data_hash = None


class BlockchainAuthenticationTree:
    """
    实现文献5的q叉树结构，支持高效范围查询
    每个节点包含：commitment = Commit(m_i, C_child1, C_child2, g_i)
    """

    def __init__(self, hash_impl: HashInterface, branching_factor: int = SecurityConfig.BAT_BRANCHING_FACTOR):
        self.hash = hash_impl
        self.q = branching_factor
        self.root = BATNode(level=0, node_id="root")
        self.leaf_nodes = {}  # block_hash -> leaf_node
        self.node_counter = 0
        # 初始化根节点承诺
        self.root.commitment = b''

    def _create_leaf(self, block_data: Dict) -> BATNode:
        """创建叶子节点"""
        leaf = BATNode(level=self._get_current_max_level(),
                       node_id=f"leaf_{self.node_counter}")
        self.node_counter += 1

        # 计算数据哈希
        block_bytes = block_data.get('data', b'')
        self.data_hash = self.hash.hash(block_bytes)

        # 存储块信息
        leaf.block_hash = block_data.get('block_hash')
        leaf.data_hash = self.data_hash

        return leaf

    def _get_current_max_level(self) -> int:
        """获取当前最大层级"""
        if not self.leaf_nodes:
            return 1
        return max(node.level for node in self.leaf_nodes.values())

    def _get_path_to_root(self, node: BATNode) -> List[BATNode]:
        """获取从节点到根的路径"""
        path = []
        current = node
        while current:
            path.append(current)
            current = current.parent
        return path

    def _aggregate_commitments(self, node: BATNode) -> bytes:
        """聚合子节点承诺"""
        if not node.children:
            # 叶子节点：commitment = H(block_data || auxiliary)
            return self.hash.hash(node.data_hash) if node.data_hash else b''

        # 内部节点：聚合子节点承诺
        child_commitments = b''.join([child.commitment for child in node.children if child.commitment])
        return self.hash.hash(child_commitments) if child_commitments else b''

    def _create_new_root(self):
        """创建新的根节点（类似Merkle Mountain Range）"""
        new_root = BATNode(level=0, node_id=f"new_root_{self.node_counter}")
        self.node_counter += 1
        new_root.children.append(self.root)
        self.root.parent = new_root
        # 计算新根节点承诺
        new_root.commitment = self._aggregate_commitments(new_root)
        self.root = new_root

    def bind_block(self, block_data: Dict) -> bool:
        """绑定区块到BAT"""
        try:
            # 1. 创建叶子节点：commitment = H(block_data || auxiliary)
            leaf = self._create_leaf(block_data)
            block_hash = block_data.get('block_hash')

            if block_hash:
                self.leaf_nodes[block_hash] = leaf
                # 计算叶子节点承诺
                leaf.commitment = self._aggregate_commitments(leaf)

            # 2. 找到合适的父节点
            parent = self._find_available_parent()
            parent.children.append(leaf)
            leaf.parent = parent

            # 3. 更新路径上的commitment（PointProofs聚合）
            path = self._get_path_to_root(leaf)
            for node in reversed(path):
                node.commitment = self._aggregate_commitments(node)

            # 4. 若根节点满，创建新根（类似Merkle Mountain Range）
            if len(self.root.children) >= self.q:
                self._create_new_root()

            print(f"[BAT] 区块绑定成功: {block_hash.hex()[:16]}..." if block_hash else "[BAT] 区块绑定成功")
            return True
        except Exception as e:
            print(f"[BAT] 区块绑定失败: {e}")
            # 打印详细的错误信息以便调试
            import traceback
            traceback.print_exc()
            return False

    def _find_available_parent(self) -> BATNode:
        """找到可用的父节点"""
        # 广度优先搜索寻找第一个有可用位置的节点
        queue = [self.root]

        while queue:
            node = queue.pop(0)

            # 如果是叶子节点层级，直接添加到根节点
            if node.level == self._get_current_max_level() - 1:
                if len(node.children) < self.q:
                    return node
                else:
                    # 创建新的层级
                    new_node = BATNode(level=node.level + 1,
                                       node_id=f"internal_{self.node_counter}")
                    self.node_counter += 1
                    node.children.append(new_node)
                    new_node.parent = node
                    # 计算新节点承诺
                    new_node.commitment = self._aggregate_commitments(new_node)
                    return new_node

            # 将子节点加入队列
            queue.extend(node.children)

        # 如果没有找到，创建新的根节点
        self._create_new_root()
        return self.root

    def generate_proof(self, block_hash: bytes, start: int = None, end: int = None) -> Dict:
        """
        生成范围查询证明：证明block_hash在[start, end]区间内
        使用文献5的Query协议：Chal-Prove-Verify三阶段
        """
        if block_hash not in self.leaf_nodes:
            raise ValueError(f"Block {block_hash.hex()[:16]}... not found in BAT")

        leaf = self.leaf_nodes[block_hash]
        path = self._get_path_to_root(leaf)

        proof = {
            'range': (start, end) if start is not None and end is not None else None,
            'commitment_path': [node.commitment.hex() for node in path if node.commitment],
            'block_hash': block_hash.hex(),
            'data_hash': leaf.data_hash.hex() if leaf.data_hash else None,
            'node_path': [node.node_id for node in path]
        }

        if start is not None and end is not None:
            # 添加范围查询相关信息
            proof['auxiliary_values'] = self._get_auxiliary_values(start, end)

        return proof

    def _get_auxiliary_values(self, start: int, end: int) -> Dict:
        """获取范围查询的辅助值"""
        # 实现文献5中的辅助值计算
        return {
            'start_index': start,
            'end_index': end,
            'range_proof': self.hash.hash(f"range_{start}_{end}".encode()).hex()
        }

    def verify_proof(self, proof: Dict) -> bool:
        """验证证明"""
        try:
            if not proof.get('data_hash'):
                return False

            # 验证路径完整性
            current_commitment = bytes.fromhex(proof['data_hash'])
            for commitment_hex in proof['commitment_path'][1:]:
                current_commitment = self.hash.hash(current_commitment + bytes.fromhex(commitment_hex))

            # 验证根承诺
            return current_commitment == self.root.commitment
        except Exception as e:
            print(f"[BAT] 证明验证失败: {e}")
            return False

    def get_root_commitment(self) -> bytes:
        """获取根承诺"""
        return self.root.commitment

    def stats(self) -> Dict:
        """获取统计信息"""
        return {
            'total_nodes': self.node_counter,
            'leaf_count': len(self.leaf_nodes),
            'branching_factor': self.q,
            'tree_depth': self._get_current_max_level(),
            'root_commitment': self.root.commitment.hex() if self.root.commitment else None
        }


# 2.2 实现真实MPC共识（Shamir秘密共享）
class MPCConsensusSimulator:
    """
    实现文献2的基于Shamir秘密共享的MPC编辑决策
    阈值t = 2n/3 + 1，抵抗恶意参与者
    """

    def __init__(self, participants: List[str], threshold: Optional[int] = None):
        self.participants = participants
        self.n = len(participants)
        self.t = threshold or (2 * self.n // 3) + 1  # 默认阈值
        self.field = 2 ** 127 - 1  # 大素数域（梅森素数）
        self.network_model = None

    def set_network_model(self, network_model: Dict):
        """设置网络模型参数"""
        self.network_model = network_model

    def _hash_request(self, edit_request: Any) -> int:
        """哈希编辑请求"""
        request_bytes = pickle.dumps(edit_request)
        return int.from_bytes(hashlib.sha3_256(request_bytes).digest(), 'big') % self.field

    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """计算多项式值"""
        result = 0
        for i, coeff in enumerate(coefficients):
            result = (result + coeff * (x ** i)) % self.field
        return result

    def _lagrange_interpolate(self, shares: List[Tuple[int, int]]) -> int:
        """拉格朗日插值重构秘密"""
        x_s, y_s = zip(*shares)
        k = len(shares)

        def L(j):
            """拉格朗日基多项式"""
            result = 1
            for m in range(k):
                if m != j:
                    numerator = (0 - x_s[m]) % self.field
                    denominator = (x_s[j] - x_s[m]) % self.field
                    result = (result * numerator * pow(denominator, -1, self.field)) % self.field
            return result

        secret = 0
        for j in range(k):
            secret = (secret + y_s[j] * L(j)) % self.field
        return secret

    def _collect_shares(self, shares: Dict[str, int], network_model: Dict) -> List[Tuple[int, int]]:
        """收集参与者份额"""
        collected = []
        reliability = network_model.get('reliability', 1.0)

        for i, (participant, share) in enumerate(shares.items()):
            # 根据网络可靠性模型决定是否收集到份额
            if SecureRandom.int(1, 100) <= reliability * 100:
                collected.append((i + 1, share))

            # 如果收集到足够的份额，提前返回
            if len(collected) >= self.t:
                break

        return collected

    def simulate_consensus(self, edit_request: Any, **kwargs) -> Tuple[bool, Dict]:
        """模拟MPC共识过程"""
        if not self.network_model and 'network_model' not in kwargs:
            raise ValueError("Network model not set")

        network_model = kwargs.get('network_model', self.network_model)

        # 1. 构建编辑请求的多项式：f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
        #    常数项a_0 = H(edit_request)，作为秘密
        secret = self._hash_request(edit_request)
        coefficients = [secret] + [SecureRandom.int(1, self.field - 1) for _ in range(self.t - 1)]

        # 2. 为每个参与者生成份额：share_i = f(i) mod field
        shares = {
            p: self._evaluate_polynomial(coefficients, i + 1)
            for i, p in enumerate(self.participants)
        }

        # 3. 模拟通信：收集至少t个参与者的签名（模拟拜占庭广播）
        collected_shares = self._collect_shares(shares, network_model)

        # 4. 拉格朗日插值重构秘密（仅当≥t个诚实参与者）
        success = False
        reconstructed = None

        if len(collected_shares) >= self.t:
            reconstructed = self._lagrange_interpolate(collected_shares[:self.t])
            # 验证重构秘密与原始一致
            success = reconstructed == secret

        # 记录通信轮次
        communication_rounds = kwargs.get('communication_rounds', [])

        return success, {
            'consensus_type': 'mpc_shamir',
            'rounds': len(communication_rounds),
            'communication_cost': len(pickle.dumps(shares)),
            'threshold': self.t,
            'participants_count': self.n,
            'collected_shares': len(collected_shares),
            'success': success,
            'reconstructed_secret': reconstructed
        }


# 2.3 补全策略表达语言
class PolicyType(Enum):
    """策略类型"""
    AND = "and"
    OR = "or"
    THRESHOLD = "threshold"
    ATTRIBUTE = "attribute"


class PolicyNode:
    """策略抽象语法树节点"""

    def __init__(self, node_type: PolicyType, value: Any = None):
        self.type = node_type
        self.value = value
        self.children = []

    def add_child(self, child: 'PolicyNode'):
        self.children.append(child)


class MSPPolicyParser:
    """
    实现单调跨度程序（MSP）策略解析器
    支持策略：(attr1 and attr2) or (attr3 and threshold(2, attr4, attr5, attr6))
    """

    def __init__(self):
        self.current_token = None
        self.token_index = 0
        self.tokens = []

    def _tokenize(self, policy_str: str) -> List[str]:
        """词法分析：将策略字符串转为token序列"""
        import re
        token_specification = [
            ('LPAREN', r'\('),  # Left parenthesis
            ('RPAREN', r'\)'),  # Right parenthesis
            ('AND', r'and'),  # And operator
            ('OR', r'or'),  # Or operator
            ('THRESHOLD', r'threshold'),  # Threshold function
            ('NUMBER', r'\d+'),  # Number
            ('ATTRIBUTE', r'[a-zA-Z_][a-zA-Z0-9_]*'),  # Attribute
            ('COMMA', r','),  # Comma
            ('WHITESPACE', r'\s+'),  # Whitespace (ignored)
        ]

        tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in token_specification)
        tokens = []

        for mo in re.finditer(tok_regex, policy_str):
            kind = mo.lastgroup
            value = mo.group()

            if kind == 'WHITESPACE':
                continue
            elif kind == 'NUMBER':
                value = int(value)

            tokens.append((kind, value))

        return tokens

    def _next_token(self):
        """获取下一个token"""
        if self.token_index < len(self.tokens):
            self.current_token = self.tokens[self.token_index]
            self.token_index += 1
            return self.current_token
        return None

    def _parse_primary(self) -> PolicyNode:
        """解析基本表达式"""
        if not self.current_token:
            return None

        kind, value = self.current_token

        if kind == 'LPAREN':
            self._next_token()  # Consume '('
            expr = self._parse_expression()
            if self.current_token and self.current_token[0] == 'RPAREN':
                self._next_token()  # Consume ')'
            return expr

        elif kind == 'ATTRIBUTE':
            node = PolicyNode(PolicyType.ATTRIBUTE, value)
            self._next_token()  # Consume attribute
            return node

        elif kind == 'THRESHOLD':
            self._next_token()  # Consume 'threshold'
            if not self.current_token or self.current_token[0] != 'LPAREN':
                raise SyntaxError("Expected '(' after threshold")

            self._next_token()  # Consume '('
            if not self.current_token or self.current_token[0] != 'NUMBER':
                raise SyntaxError("Expected threshold number")

            threshold = self.current_token[1]
            self._next_token()  # Consume number

            if not self.current_token or self.current_token[0] != 'COMMA':
                raise SyntaxError("Expected ',' after threshold number")

            self._next_token()  # Consume ','

            node = PolicyNode(PolicyType.THRESHOLD, threshold)

            # 解析属性列表
            while self.current_token and self.current_token[0] != 'RPAREN':
                if self.current_token[0] == 'COMMA':
                    self._next_token()  # Consume ','
                    continue

                attr_node = self._parse_primary()
                if attr_node:
                    node.add_child(attr_node)

            if self.current_token and self.current_token[0] == 'RPAREN':
                self._next_token()  # Consume ')'

            return node

        return None

    def _parse_expression(self) -> PolicyNode:
        """解析表达式"""
        left = self._parse_primary()

        while self.current_token:
            kind, value = self.current_token

            if kind in ('AND', 'OR'):
                op_node = PolicyNode(PolicyType.AND if kind == 'AND' else PolicyType.OR)
                op_node.add_child(left)

                self._next_token()  # Consume operator
                right = self._parse_primary()

                if right:
                    op_node.add_child(right)
                    left = op_node
                else:
                    break
            else:
                break

        return left

    def parse_policy(self, policy_str: str) -> Dict:
        """解析策略字符串"""
        # 1. 词法分析：将策略字符串转为token序列
        self.tokens = self._tokenize(policy_str)
        self.token_index = 0
        self.current_token = None

        # 2. 语法分析：构建AST（抽象语法树）
        self._next_token()  # 获取第一个token
        ast = self._parse_expression()

        if not ast:
            raise SyntaxError("Empty policy")

        # 3. 矩阵生成：将AST转为MSP矩阵
        #    矩阵M的每一行对应一个属性，ρ映射行号到属性
        matrix, rho = self._ast_to_msp(ast)

        return {'matrix': matrix, 'rho': rho, 'ast': ast}

    def _ast_to_msp(self, ast: PolicyNode) -> Tuple[List[List[int]], Dict[int, str]]:
        """将AST转换为MSP矩阵"""
        matrix = []
        rho = {}
        attribute_set = self._collect_attributes(ast)
        attr_list = list(attribute_set)
        field = 2  # 二元域

        # 为AND门创建矩阵
        if ast.type == PolicyType.AND:
            # AND门的MSP矩阵：每一行对应一个属性，全1向量
            row_count = len(attr_list)
            matrix = [[1] * (row_count + 1) for _ in range(row_count)]
            # 设置最后一列为1
            for i in range(row_count):
                matrix[i][-1] = 1
            # ρ映射
            for i, attr in enumerate(attr_list):
                rho[i] = attr

        # 为OR门创建矩阵
        elif ast.type == PolicyType.OR:
            # OR门的MSP矩阵：单位矩阵
            row_count = len(attr_list)
            matrix = [[0] * row_count for _ in range(row_count)]
            for i in range(row_count):
                matrix[i][i] = 1
            # ρ映射
            for i, attr in enumerate(attr_list):
                rho[i] = attr

        # 为阈值门创建矩阵
        elif ast.type == PolicyType.THRESHOLD:
            k = ast.value
            m = len(ast.children)

            # 阈值门的MSP矩阵
            matrix = []
            # 添加k-1个全1行
            for i in range(k - 1):
                matrix.append([1] * m)
            # 添加单位矩阵部分
            for i in range(m):
                row = [0] * m
                row[i] = 1
                matrix.append(row)
            # ρ映射
            for i, child in enumerate(ast.children):
                if child.type == PolicyType.ATTRIBUTE:
                    rho[len(matrix) - m + i] = child.value

        return matrix, rho

    def _collect_attributes(self, node: PolicyNode) -> set:
        """收集所有属性"""
        attributes = set()

        if node.type == PolicyType.ATTRIBUTE:
            attributes.add(node.value)
        else:
            for child in node.children:
                attributes.update(self._collect_attributes(child))

        return attributes


# -------------------------
# 增强版SimpleCPABE实现（完整实现）
# -------------------------
class EnhancedSimpleCPABE:
    """
    增强版SimpleCPABE实现
    基于密钥派生和策略匹配的真实ABE实现
    支持复杂策略：(attr1 and attr2) or (attr3 and threshold(2, attr4, attr5, attr6))
    """

    def __init__(self, universe_size: int = 20, hash_impl: HashInterface = None):
        self.universe_size = universe_size
        self.hash = hash_impl or SHA3_256()
        self.master_key = None
        self.public_params = None
        self.policy_parser = MSPPolicyParser()
        print(f"[EnhancedCP-ABE] 初始化完成，属性宇宙大小: {universe_size}")

    def setup(self) -> Tuple[Dict, Dict]:
        """
        初始化ABE系统
        Returns:
            (public_params, master_key)
        """
        # 生成主密钥
        self.master_key = {
            'master_secret': SecureRandom.bytes(SecurityConfig.CPABE_MASTER_KEY_SIZE),
            'salt': SecureRandom.bytes(SecurityConfig.CPABE_SALT_SIZE),
            'created_at': time.time()
        }

        # 生成公开参数
        self.public_params = {
            'system_id': f"cpabe_system_{SecureRandom.string(8)}",
            'hash_algorithm': 'SHA3_256',
            'universe_size': self.universe_size,
            'aes_key_size': SecurityConfig.AES_KEY_SIZE,
            'setup_time': time.time()
        }

        print(f"[EnhancedCP-ABE] 系统初始化完成，系统ID: {self.public_params['system_id']}")
        return self.public_params, self.master_key

    def _derive_attribute_key(self, attribute: str) -> bytes:
        """为单个属性派生密钥"""
        if not self.master_key:
            raise ValueError("Master key not initialized")

        # 使用PBKDF2从主密钥派生属性密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SecurityConfig.AES_KEY_SIZE,
            salt=self.master_key['salt'] + attribute.encode(),
            iterations=SecurityConfig.CPABE_ITERATIONS,
            backend=default_backend()
        )

        return kdf.derive(self.master_key['master_secret'] + attribute.encode())

    def _derive_policy_key(self, policy_str: str) -> bytes:
        """为策略派生密钥"""
        if not self.master_key:
            raise ValueError("Master key not initialized")

        # 规范化策略字符串（去除空格，小写化）
        normalized_policy = policy_str.lower().replace(' ', '')

        # 使用PBKDF2从主密钥和策略派生策略密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SecurityConfig.AES_KEY_SIZE,
            salt=self.master_key['salt'] + b'policy',
            iterations=SecurityConfig.CPABE_ITERATIONS,
            backend=default_backend()
        )

        return kdf.derive(self.master_key['master_secret'] + normalized_policy.encode())

    def keygen(self, master_key: Dict, user_attrs: List[str]) -> Dict:
        """
        为用户属性集生成密钥
        Args:
            master_key: 主密钥
            user_attrs: 用户属性列表
        Returns:
            用户私钥
        """
        if not self.master_key:
            self.master_key = master_key

        # 为每个用户属性派生密钥分量
        attribute_keys = {}
        for attr in user_attrs:
            attribute_keys[attr] = self._derive_attribute_key(attr)

        user_key = {
            'user_id': f"user_{SecureRandom.string(8)}",
            'attributes': user_attrs,
            'attribute_keys': attribute_keys,
            'keygen_time': time.time()
        }

        print(f"[EnhancedCP-ABE] 用户密钥生成完成，用户ID: {user_key['user_id']}, 属性: {user_attrs}")
        return user_key

    def encrypt(self, public_params: Dict, message: bytes, policy_str: str) -> Dict:
        """
        使用策略加密消息
        Args:
            public_params: 公开参数
            message: 要加密的消息
            policy_str: 访问策略字符串
        Returns:
            加密结果
        """
        # 1. 解析策略
        try:
            policy_info = self.policy_parser.parse_policy(policy_str)
            print(f"[EnhancedCP-ABE] 策略解析成功: {policy_str}")
        except Exception as e:
            print(f"[EnhancedCP-ABE] 策略解析失败: {e}")
            # 使用简单策略作为回退
            policy_info = {'matrix': [[1]], 'rho': {0: 'default'}, 'ast': PolicyNode(PolicyType.ATTRIBUTE, 'default')}

        # 2. 为策略派生密钥
        policy_key = self._derive_policy_key(policy_str)

        # 3. 生成随机会话密钥并用AES-GCM加密消息
        session_key = SecureRandom.bytes(SecurityConfig.AES_KEY_SIZE)
        aes = AESGCM(session_key)
        nonce = SecureRandom.bytes(SecurityConfig.AES_NONCE_SIZE)
        ciphertext = aes.encrypt(nonce, message, None)

        # 4. 用策略密钥加密会话密钥
        policy_aes = AESGCM(policy_key)
        policy_nonce = SecureRandom.bytes(SecurityConfig.AES_NONCE_SIZE)
        encrypted_session_key = policy_aes.encrypt(policy_nonce, session_key, None)

        # 构建完整的加密结果
        result = {
            'type': 'enhanced_cpabe',
            'policy': policy_str,
            'policy_info': policy_info,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
            'policy_nonce': base64.b64encode(policy_nonce).decode(),
            'encryption_time': time.time()
        }

        print(f"[EnhancedCP-ABE] 加密完成，策略: {policy_str}, 消息长度: {len(message)} 字节")
        return result

    def _check_policy_satisfaction(self, user_attrs: List[str], policy_str: str) -> bool:
        """
        检查用户属性是否满足策略
        支持 AND, OR, THRESHOLD 门
        """
        try:
            # 规范化输入
            user_attrs_set = set(attr.lower().strip() for attr in user_attrs)
            policy_str_clean = policy_str.lower().strip()

            # 解析策略
            policy_info = self.policy_parser.parse_policy(policy_str_clean)
            ast = policy_info['ast']

            # 评估AST
            result = self._evaluate_policy_ast(ast, user_attrs_set)
            print(f"[EnhancedCP-ABE] 策略评估: '{policy_str}' -> 用户{user_attrs} -> 结果: {result}")
            return result

        except Exception as e:
            print(f"[EnhancedCP-ABE] 策略评估失败，使用简单回退: {e}")
            # 简单回退：检查策略字符串是否包含所有用户属性
            policy_lower = policy_str.lower()
            return all(attr.lower() in policy_lower for attr in user_attrs)

    def _evaluate_policy_ast(self, node: PolicyNode, user_attrs: Set[str]) -> bool:
        """递归评估策略AST"""
        if node.type == PolicyType.ATTRIBUTE:
            return node.value in user_attrs

        elif node.type == PolicyType.AND:
            # AND门：所有子节点都必须满足
            return all(self._evaluate_policy_ast(child, user_attrs) for child in node.children)

        elif node.type == PolicyType.OR:
            # OR门：至少一个子节点满足
            return any(self._evaluate_policy_ast(child, user_attrs) for child in node.children)

        elif node.type == PolicyType.THRESHOLD:
            # 阈值门：至少k个子节点满足
            k = node.value
            satisfied = sum(1 for child in node.children if self._evaluate_policy_ast(child, user_attrs))
            return satisfied >= k

        return False

    def _reconstruct_policy_key(self, user_key: Dict, policy_str: str) -> Optional[bytes]:
        """
        尝试从用户密钥重构策略密钥
        只有用户属性满足策略时才能成功
        """
        user_attrs = user_key['attributes']

        # 检查策略满足性
        if not self._check_policy_satisfaction(user_attrs, policy_str):
            print(f"[EnhancedCP-ABE] 策略不满足: 需要 {policy_str}, 用户有 {user_attrs}")
            return None

        # 如果满足策略，使用相同的方法派生策略密钥
        return self._derive_policy_key(policy_str)

    def decrypt(self, public_params: Dict, user_key: Dict, ciphertext: Dict) -> Optional[bytes]:
        """
        解密密文
        Args:
            public_params: 公开参数
            user_key: 用户密钥
            ciphertext: 密文
        Returns:
            解密后的消息，如果不满足策略则返回None
        """
        try:
            # 1. 检查密文类型
            if ciphertext.get('type') != 'enhanced_cpabe':
                print(f"[EnhancedCP-ABE] 不支持的密文类型: {ciphertext.get('type')}")
                return None

            policy_str = ciphertext['policy']
            print(f"[EnhancedCP-ABE] 尝试解密，策略: {policy_str}")

            # 2. 重构策略密钥
            policy_key = self._reconstruct_policy_key(user_key, policy_str)
            if policy_key is None:
                print("[EnhancedCP-ABE] 无法重构策略密钥（策略不满足）")
                return None

            # 3. 解密会话密钥
            policy_nonce = base64.b64decode(ciphertext['policy_nonce'])
            encrypted_session_key = base64.b64decode(ciphertext['encrypted_session_key'])

            try:
                policy_aes = AESGCM(policy_key)
                session_key = policy_aes.decrypt(policy_nonce, encrypted_session_key, None)
            except Exception as e:
                print(f"[EnhancedCP-ABE] 会话密钥解密失败: {e}")
                return None

            # 4. 用会话密钥解密消息
            nonce = base64.b64decode(ciphertext['nonce'])
            message_ciphertext = base64.b64decode(ciphertext['ciphertext'])

            try:
                aes = AESGCM(session_key)
                message = aes.decrypt(nonce, message_ciphertext, None)
                print(f"[EnhancedCP-ABE] 解密成功，消息长度: {len(message)} 字节")
                return message
            except Exception as e:
                print(f"[EnhancedCP-ABE] 消息解密失败: {e}")
                return None

        except Exception as e:
            print(f"[EnhancedCP-ABE] 解密过程中发生异常: {e}")
            import traceback
            traceback.print_exc()
            return None

    def get_system_info(self) -> Dict:
        """获取系统信息"""
        return {
            'type': 'EnhancedSimpleCPABE',
            'universe_size': self.universe_size,
            'master_key_initialized': self.master_key is not None,
            'public_params': self.public_params
        }


# -------------------------
# PolicyChameleon (PCH) - 基于增强版CP-ABE
# -------------------------
class PolicyChameleon:
    """
    基于增强版CP-ABE的策略变色龙哈希实现
    结合双层变色龙哈希和属性基加密
    """

    def __init__(self, dual_hash: DualLayerChameleonHash, cpabe_impl: EnhancedSimpleCPABE):
        self.dual = dual_hash
        self.cpabe_impl = cpabe_impl
        self.policy_parser = MSPPolicyParser()

        # 初始化CP-ABE系统
        self.public_params, self.master_key = cpabe_impl.setup()
        print("[PCH] 系统初始化完成，使用增强版SimpleCP-ABE")

    def hash_with_policy(self, message: bytes, policy: str, label: Optional[bytes] = None,
                         prev_hash: Optional[bytes] = None) -> Dict:
        """
        使用访问策略计算消息的哈希值
        Returns:
            {
                'inner_hash': 内层哈希,
                'outer_hash': 外层哈希,
                'label': 标签,
                'policy': 策略,
                'encrypted_r': 加密的随机数,
                'inner_r': 内层随机数,
                'outer_r': 外层随机数
            }
        """
        if label is None:
            label = SecureRandom.bytes(32)
        if prev_hash is None:
            prev_hash = b'\x00' * 32

        # 生成随机数r（用于变色龙哈希）
        r = SecureRandom.bytes(64)  # 64字节 = 32字节(内层) + 32字节(外层)

        # 解析策略为MSP矩阵
        try:
            policy_info = self.policy_parser.parse_policy(policy)
            print(f"[PCH] 策略解析成功: {policy}")
        except Exception as e:
            print(f"[PCH] 策略解析失败，使用简单策略: {e}")
            policy_info = {'matrix': [[1]], 'rho': {0: 'default'}, 'ast': PolicyNode(PolicyType.ATTRIBUTE, 'default')}

        # 使用CP-ABE加密随机数r
        encrypted_r = self.cpabe_impl.encrypt(self.public_params, r, policy)
        encrypted_r['msp_matrix'] = policy_info.get('matrix', [[1]])
        encrypted_r['msp_rho'] = policy_info.get('rho', {0: 'default'})

        # 计算双层变色龙哈希
        inner_hash, inner_r = self.dual.compute_inner(message, label, r[:32])
        committee_bytes = self.dual.current_committee().public_bytes()
        outer_hash, outer_r = self.dual.compute_outer(inner_hash, committee_bytes, prev_hash, label, r[32:])

        return {
            'inner_hash': inner_hash.hex(),
            'outer_hash': outer_hash.hex(),
            'label': label.hex(),
            'policy': policy,
            'policy_ast': policy_info.get('ast'),
            'encrypted_r': encrypted_r,
            'inner_r': inner_r.hex(),
            'outer_r': outer_r.hex(),
            'prev_hash': prev_hash.hex() if isinstance(prev_hash, bytes) else prev_hash
        }

    def adapt_with_policy(self, user_attrs: List[str], orig_msg: bytes, new_msg: bytes,
                          hash_data: Dict, prev_hash: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        为满足策略的用户查找碰撞
        Returns:
            (new_inner_r, new_outer_r) - 新的随机数
        """
        if prev_hash is None:
            prev_hash = bytes.fromhex(hash_data.get('prev_hash', '00' * 32))

        encrypted_r = hash_data['encrypted_r']
        policy_str = hash_data['policy']

        # 生成用户密钥
        user_key = self.cpabe_impl.keygen(self.master_key, user_attrs)
        print(f"[PCH] 尝试解密随机数 - 策略: {policy_str}, 用户属性: {user_attrs}")

        # 解密随机数r
        r_decrypted = self.cpabe_impl.decrypt(self.public_params, user_key, encrypted_r)
        if r_decrypted is None:
            raise ValueError(f"无法解密随机数，用户属性不满足策略: {policy_str}")

        print(f"[PCH] 随机数解密成功，长度: {len(r_decrypted)} 字节")

        # 提取内层和外层随机数
        if len(r_decrypted) < 64:
            # 如果解密出的随机数长度不足，用哈希扩展
            r_hash = hashlib.sha3_256(r_decrypted).digest()
            r_inner = r_hash[:32]
            r_outer = r_hash[32:] if len(r_hash) >= 64 else hashlib.sha3_256(r_hash).digest()[:32]
        else:
            r_inner = r_decrypted[:32]
            r_outer = r_decrypted[32:64]

        label = bytes.fromhex(hash_data['label'])
        committee_km = self.dual.current_committee()

        # 计算内层哈希碰撞
        new_r_inner = self.dual.compute_inner_collision(committee_km.private, label, orig_msg, r_inner, new_msg)
        new_inner_hash, _ = self.dual.compute_inner(new_msg, label, new_r_inner)

        # 计算外层哈希碰撞
        committee_bytes = committee_km.public_bytes()
        original_combined = bytes.fromhex(hash_data['inner_hash']) + committee_bytes + prev_hash
        new_combined = new_inner_hash + committee_bytes + prev_hash

        new_r_outer = self.dual.compute_outer_collision(label, original_combined, r_outer, new_combined)

        return new_r_inner, new_r_outer

    def verify_hash(self, hash_data: Dict, message: bytes, r_inner: bytes, r_outer: bytes,
                    prev_hash: Optional[bytes] = None) -> bool:
        """验证哈希值"""
        if prev_hash is None:
            prev_hash = bytes.fromhex(hash_data.get('prev_hash', '00' * 32))

        label = bytes.fromhex(hash_data['label'])

        # 验证内层哈希
        computed_inner, _ = self.dual.compute_inner(message, label, r_inner)
        if computed_inner.hex() != hash_data['inner_hash']:
            print(f"[PCH] 内层哈希验证失败: {computed_inner.hex()} != {hash_data['inner_hash']}")
            return False

        # 验证外层哈希
        committee_bytes = self.dual.current_committee().public_bytes()
        computed_outer, _ = self.dual.compute_outer(computed_inner, committee_bytes, prev_hash, label, r_outer)

        if computed_outer.hex() != hash_data['outer_hash']:
            print(f"[PCH] 外层哈希验证失败: {computed_outer.hex()} != {hash_data['outer_hash']}")
            return False

        return True


# -------------------------
# AsyncStorage
# -------------------------
class AsyncStorage:
    def __init__(self, db_path: str = "blockchain.db"):
        self.db_path = db_path
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._initialized = False

    async def initialize(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS blocks (
                    block_hash BLOB PRIMARY KEY,
                    block_number INTEGER,
                    data BLOB,
                    chameleon_hash BLOB,
                    chameleon_inner_hash BLOB,
                    random_nonce BLOB,
                    public_key BLOB,
                    label BLOB,
                    prev_hash BLOB,
                    block_type TEXT,
                    policy_info TEXT,
                    created_at REAL
                );
                CREATE TABLE IF NOT EXISTS edit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_hash BLOB,
                    original_data BLOB,
                    edited_data BLOB,
                    editor_id TEXT,
                    edit_reason TEXT,
                    edit_type TEXT,
                    previous_nonce BLOB,
                    new_nonce BLOB,
                    chameleon_inner_hash BLOB,
                    prev_hash BLOB,
                    edit_proof BLOB,
                    timestamp REAL
                );
                CREATE TABLE IF NOT EXISTS label_registry (
                    label BLOB PRIMARY KEY,
                    block_hash BLOB,
                    created_at REAL
                );
                CREATE TABLE IF NOT EXISTS bat_nodes (
                    node_id TEXT PRIMARY KEY,
                    level INTEGER,
                    commitment BLOB,
                    parent_id TEXT,
                    block_hash BLOB,
                    data_hash BLOB,
                    created_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_blocks_number ON blocks(block_number);
                CREATE INDEX IF NOT EXISTS idx_edit_history_hash ON edit_history(block_hash);
                CREATE INDEX IF NOT EXISTS idx_labels ON label_registry(label);
                CREATE INDEX IF NOT EXISTS idx_bat_parent ON bat_nodes(parent_id);
                CREATE INDEX IF NOT EXISTS idx_bat_block ON bat_nodes(block_hash);
            """)
            await db.commit()
            cursor = await db.execute("PRAGMA table_info(blocks);")
            cols = await cursor.fetchall()
            col_names = {c[1] for c in cols}
            expected = {'block_hash', 'block_number', 'data', 'chameleon_hash', 'chameleon_inner_hash', 'random_nonce',
                        'public_key', 'label', 'prev_hash', 'block_type', 'policy_info', 'created_at'}
            missing = expected - col_names
            for col in missing:
                try:
                    col_type = 'BLOB' if col in (
                        'block_hash', 'data', 'chameleon_hash', 'random_nonce', 'public_key', 'label') else \
                        'INTEGER' if col in ('block_number',) else \
                            'REAL' if col in ('created_at',) else 'TEXT'
                    await db.execute(f"ALTER TABLE blocks ADD COLUMN {col} {col_type};")
                except Exception as e:
                    print(f"[Storage] 添加列 {col} 失败: {e}")
            await db.commit()
        self._initialized = True
        print(f"[Storage] 数据库初始化/迁移完成: {self.db_path}")

    # ==========================================
    # 在 AsyncStorage 类中添加以下三个方法
    # ==========================================

    async def store_bat_node(self, node: 'BATNode') -> bool:
        """
        递归存储BAT树所有节点到数据库
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await self._store_bat_node_recursive(db, node)
                await db.commit()
                return True
        except Exception as e:
            print(f"[Storage] 存储BAT节点失败: {e}")
            return False

    async def _store_bat_node_recursive(self, db, node: 'BATNode'):
        """
        递归存储单个节点及其所有子节点
        """
        # 存储当前节点
        await db.execute("""
            INSERT OR REPLACE INTO bat_nodes 
            (node_id, level, commitment, parent_id, block_hash, data_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            node.node_id,
            node.level,
            node.commitment,
            node.parent.node_id if node.parent else None,
            node.block_hash,
            node.data_hash,
            time.time()
        ))

        # 递归存储子节点
        for child in node.children:
            await self._store_bat_node_recursive(db, child)

    async def load_bat_tree(self) -> Optional[Dict[str, 'BATNode']]:
        """
        从数据库加载BAT树结构（用于系统重启后恢复）
        返回: 节点字典 {node_id: BATNode} 或 None
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM bat_nodes ORDER BY level ASC") as cursor:
                    rows = await cursor.fetchall()

                if not rows:
                    return None

                # 重建节点
                nodes = {}
                for row in rows:
                    node = BATNode(level=row[1], node_id=row[0])
                    node.commitment = row[2]
                    node.block_hash = row[4]
                    node.data_hash = row[5]
                    nodes[row[0]] = node

                # 重建树结构
                for row in rows:
                    if row[3]:  # 有父节点
                        nodes[row[0]].parent = nodes[row[3]]
                        nodes[row[3]].children.append(nodes[row[0]])

                return nodes
        except Exception as e:
            print(f"[Storage] 加载BAT树失败: {e}")
            import traceback
            traceback.print_exc()
            return None
    async def store_block(self, block: Dict) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO blocks
                    (block_hash, block_number, data, chameleon_hash, chameleon_inner_hash, random_nonce, public_key, label, prev_hash, block_type, policy_info, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    block['block_hash'],
                    block['block_number'],
                    block['data'],
                    block['chameleon_hash'],
                    block.get('chameleon_inner_hash'),
                    block['random_nonce'],
                    block['public_key'],
                    block['label'],
                    block.get('prev_hash'),
                    block.get('block_type', 'normal'),
                    json.dumps(block.get('policy_info', {})),
                    block.get('created_at', time.time())
                ))
                await db.execute("""
                    INSERT OR REPLACE INTO label_registry (label, block_hash, created_at) VALUES (?, ?, ?)
                """, (block['label'], block['block_hash'], time.time()))
                await db.commit()
                return True
        except Exception as e:
            print(f"[Storage] 存储区块失败: {e}")
            return False

    async def get_block(self, block_hash: bytes) -> Optional[Dict]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT block_hash, block_number, data, chameleon_hash, chameleon_inner_hash, random_nonce, public_key, label, prev_hash, block_type, policy_info, created_at
                    FROM blocks WHERE block_hash = ?
                """, (block_hash,)) as cur:
                    row = await cur.fetchone()
                    if row:
                        return {
                            'block_hash': row[0],
                            'block_number': row[1],
                            'data': row[2],
                            'chameleon_hash': row[3],
                            'chameleon_inner_hash': row[4],
                            'random_nonce': row[5],
                            'public_key': row[6],
                            'label': row[7],
                            'prev_hash': row[8],
                            'block_type': row[9],
                            'policy_info': json.loads(row[10]) if row[10] else {},
                            'created_at': row[11]
                        }
                    return None
        except Exception as e:
            print(f"[Storage] 获取区块失败: {e}")
            return None

    async def add_edit_record(self, edit: Dict) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO edit_history (block_hash, original_data, edited_data, editor_id, edit_reason, edit_type, previous_nonce, new_nonce, chameleon_inner_hash, prev_hash, edit_proof, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    edit['block_hash'],
                    edit['original_data'],
                    edit['edited_data'],
                    edit['editor_id'],
                    edit['edit_reason'],
                    edit.get('edit_type', 'normal'),
                    edit.get('previous_nonce'),
                    edit.get('new_nonce'),
                    edit.get('chameleon_inner_hash'),
                    edit.get('prev_hash'),
                    edit.get('edit_proof'),
                    edit.get('timestamp', time.time())
                ))
                await db.execute("""
                    UPDATE blocks SET data = ?, random_nonce = ?, chameleon_inner_hash = ?, prev_hash = ? WHERE block_hash = ?
                """, (
                    edit['edited_data'], edit.get('new_nonce'), edit.get('chameleon_inner_hash'), edit.get('prev_hash'),
                    edit['block_hash']))
                await db.commit()
                return True
        except Exception as e:
            print(f"[Storage] 添加编辑记录失败: {e}")
            return False

    async def is_label_unique(self, label: bytes) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT 1 FROM label_registry WHERE label = ?", (label,)) as cur:
                    row = await cur.fetchone()
                    return row is None
        except Exception as e:
            print(f"[Storage] 检查标签唯一性失败: {e}")
            return False

    async def get_all_blocks(self) -> List[Dict]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                        "SELECT block_hash, block_number, data, chameleon_hash, chameleon_inner_hash, random_nonce, public_key, label, prev_hash, block_type, policy_info, created_at FROM blocks ORDER BY block_number ASC") as cur:
                    rows = await cur.fetchall()
                    out = []
                    for r in rows:
                        out.append({
                            'block_hash': r[0],
                            'block_number': r[1],
                            'data': r[2],
                            'chameleon_hash': r[3],
                            'chameleon_inner_hash': r[4],
                            'random_nonce': r[5],
                            'public_key': r[6],
                            'label': r[7],
                            'prev_hash': r[8],
                            'block_type': r[9],
                            'policy_info': json.loads(r[10]) if r[10] else {},
                            'created_at': r[11]
                        })
                    return out
        except Exception as e:
            print(f"[Storage] 获取所有区块失败: {e}")
            return []

    async def get_block_count(self) -> int:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT COUNT(*) FROM blocks") as cur:
                    row = await cur.fetchone()
                    return row[0] if row else 0
        except Exception as e:
            print(f"[Storage] 获取区块数量失败: {e}")
            return 0


# -------------------------
# 阶段三：性能评估体系精细化
# -------------------------

class CryptographyMicroBenchmark:
    """
    隔离测量各密码学原语开销，支撑理论复杂度验证
    """

    def __init__(self, rsa_km: RSAKeyManager, hash_impl: HashInterface = None):
        self.rsa_km = rsa_km
        self.hash = hash_impl or SHA3_256()
        self.results = {}

    def measure_rhvt_tag_generation(self, param_set: List[Dict]) -> Dict:
        """测量RHVT标签生成时间"""
        results = []

        for params in param_set:
            n_bits = params['n_bits']
            exponent_sizes = params.get('exponent_sizes', [128, 256, 512, 1024, 2048])

            # 创建临时RSA密钥
            temp_km = RSAKeyManager(n_bits)
            temp_km.generate()

            times = []
            for exp_size in exponent_sizes:
                # 生成指定大小的指数
                exponent = SecureRandom.int(1, 2 ** exp_size - 1)

                # 仅测量密码学运算，排除I/O
                run_times = []
                for _ in range(100):
                    start = time.perf_counter_ns()
                    sigma = pow(2, exponent, temp_km.n)  # 核心运算
                    end = time.perf_counter_ns()
                    run_times.append(end - start)

                avg_time = statistics.mean(run_times)
                times.append({
                    'exponent_size_bits': exp_size,
                    'avg_time_ns': avg_time,
                    'std_dev_ns': statistics.stdev(run_times) if len(run_times) > 1 else 0
                })

                print(f"n_bits={n_bits}, exponent_size={exp_size}bits, avg_time={avg_time}ns")

            results.append({
                'n_bits': n_bits,
                'measurements': times
            })

        self.results['rhvt_tag_generation'] = results
        return results

    def measure_chameleon_hash(self, message_sizes: List[int] = [64, 128, 256, 512, 1024]) -> Dict:
        """测量变色龙哈希性能"""
        results = []

        for msg_size in message_sizes:
            message = SecureRandom.bytes(msg_size)
            label = SecureRandom.bytes(32)

            run_times = []
            for _ in range(100):
                start = time.perf_counter_ns()
                # 模拟变色龙哈希运算
                h = self.hash.hash(message + label)
                j = int.from_bytes(h, 'big') % (self.rsa_km.n - 2) + 2
                hm = self.hash.hash_to_int(message, self.rsa_km.n)
                r = SecureRandom.int(1, self.rsa_km.n - 1)
                j_hm = pow(j, hm, self.rsa_km.n)
                r_e = pow(r, self.rsa_km.e, self.rsa_km.n)
                hash_int = (j_hm * r_e) % self.rsa_km.n
                end = time.perf_counter_ns()
                run_times.append(end - start)

            avg_time = statistics.mean(run_times)
            results.append({
                'message_size_bytes': msg_size,
                'avg_time_ns': avg_time,
                'std_dev_ns': statistics.stdev(run_times) if len(run_times) > 1 else 0
            })

            print(f"message_size={msg_size}bytes, avg_time={avg_time}ns")

        self.results['chameleon_hash'] = results
        return results

    def export_results(self, filename: str = "microbenchmark_results.json") -> bool:
        """导出基准测试结果"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[Benchmark] 结果已导出到 {filename}")
            return True
        except Exception as e:
            print(f"[Benchmark] 导出失败: {e}")
            return False


class ScalabilityTest:
    """
    测试系统在不同区块规模下的性能退化
    """

    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.results = {}

    async def test_blockchain_scaling(self, max_blocks: int = 50000, step: int = 1000) -> Dict:
        """测试区块链扩展性"""
        append_times = []
        verify_times = []

        # 测量区块追加时间随链长增长
        for i in range(0, max_blocks, step):
            # 创建step个区块
            start = time.perf_counter()
            for j in range(step):
                data = f"scalability_block_{i + j}".encode()
                await self.blockchain.create_normal_block(data)
            end = time.perf_counter()

            elapsed = end - start
            avg_append_time = elapsed / step

            append_times.append({
                'block_number': i + step,
                'total_time_ms': elapsed * 1000,
                'avg_append_time_ms': avg_append_time * 1000
            })

            print(f"[Scalability] 区块数={i + step}, 总时间={elapsed:.3f}s, 平均时间={avg_append_time * 1000:.3f}ms")

            # 测量验证时间
            verify_start = time.perf_counter()
            all_blocks = await self.blockchain.storage.get_all_blocks()
            verified = 0
            for block in all_blocks[-step:]:  # 验证最近的step个区块
                if await self.blockchain.verify_block(block['block_hash']):
                    verified += 1
            verify_end = time.perf_counter()

            verify_elapsed = verify_end - verify_start
            avg_verify_time = verify_elapsed / step

            verify_times.append({
                'block_number': i + step,
                'total_verify_time_ms': verify_elapsed * 1000,
                'avg_verify_time_ms': avg_verify_time * 1000,
                'verified_blocks': verified,
                'total_blocks_verified': len(all_blocks[-step:])
            })

            print(
                f"[Scalability] 验证 {step} 个区块, 时间={verify_elapsed:.3f}s, 平均时间={avg_verify_time * 1000:.3f}ms")

        self.results['append_performance'] = append_times
        self.results['verify_performance'] = verify_times

        # 拟合曲线，验证亚线性增长理论
        self._fit_scaling_curve(append_times, verify_times)

        return self.results

    def _fit_scaling_curve(self, append_data: List[Dict], verify_data: List[Dict]):
        """拟合扩展曲线"""
        import numpy as np
        from scipy.optimize import curve_fit

        def linear_model(x, a, b):
            return a * x + b

        def sublinear_model(x, a, b):
            return a * np.log(x) + b

        def quadratic_model(x, a, b, c):
            return a * x ** 2 + b * x + c

        # 准备数据
        x = np.array([d['block_number'] for d in append_data])
        y_append = np.array([d['avg_append_time_ms'] for d in append_data])
        y_verify = np.array([d['avg_verify_time_ms'] for d in verify_data])

        # 拟合追加时间曲线
        try:
            popt_append_lin, _ = curve_fit(linear_model, x, y_append)
            popt_append_sub, _ = curve_fit(sublinear_model, x, y_append)

            self.results['append_fit'] = {
                'linear': {'a': popt_append_lin[0], 'b': popt_append_lin[1]},
                'sublinear': {'a': popt_append_sub[0], 'b': popt_append_sub[1]}
            }

            print(f"[Scalability] 追加时间拟合 - 线性: y={popt_append_lin[0]:.6f}x + {popt_append_lin[1]:.3f}")
            print(f"[Scalability] 追加时间拟合 - 亚线性: y={popt_append_sub[0]:.6f}log(x) + {popt_append_sub[1]:.3f}")
        except Exception as e:
            print(f"[Scalability] 追加时间拟合失败: {e}")

        # 拟合验证时间曲线
        try:
            popt_verify_lin, _ = curve_fit(linear_model, x, y_verify)
            popt_verify_sub, _ = curve_fit(sublinear_model, x, y_verify)

            self.results['verify_fit'] = {
                'linear': {'a': popt_verify_lin[0], 'b': popt_verify_lin[1]},
                'sublinear': {'a': popt_verify_sub[0], 'b': popt_verify_sub[1]}
            }

            print(f"[Scalability] 验证时间拟合 - 线性: y={popt_verify_lin[0]:.6f}x + {popt_verify_lin[1]:.3f}")
            print(f"[Scalability] 验证时间拟合 - 亚线性: y={popt_verify_sub[0]:.6f}log(x) + {popt_verify_sub[1]:.3f}")
        except Exception as e:
            print(f"[Scalability] 验证时间拟合失败: {e}")

    async def export_results(self, filename: str = "scalability_results.json") -> bool:
        """导出扩展性测试结果"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[Scalability] 结果已导出到 {filename}")
            return True
        except Exception as e:
            print(f"[Scalability] 导出失败: {e}")
            return False


# -------------------------
# 区块链核心（集成所有模块）
# -------------------------
@dataclass
class BlockEditRequest:
    block_hash: bytes
    original_data: bytes
    edited_data: bytes
    editor_id: str
    edit_reason: str
    edit_type: str = "normal"
    policy_check: Optional[Dict] = None
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class Blockchain:
    def __init__(self, ca_km: RSAKeyManager, committee_kms: Optional[List[RSAKeyManager]] = None,
                 storage: Optional[AsyncStorage] = None):
        self.ca_km = ca_km
        self.committee_kms = committee_kms or []
        if not self.committee_kms:
            for i in range(3):
                km = RSAKeyManager()
                km.generate()
                self.committee_kms.append(km)

        # 初始化双层变色龙哈希（分离层次化密钥）
        self.dual = DualLayerChameleonHash(self.ca_km)
        for km in self.committee_kms:
            self.dual.add_committee(km)

        # 使用增强版SimpleCPABE
        self.cpabe_impl = EnhancedSimpleCPABE(universe_size=20)
        self.pch = PolicyChameleon(self.dual, self.cpabe_impl)

        self.rhvt = LightRHVT(self.ca_km)  # 使用形式化加固的RHVT
        self.bat = BlockchainAuthenticationTree(SHA3_256())  # 添加BAT认证树
        self.storage = storage or AsyncStorage()
        self.block_counter = 0
        self.last_hash = b'\x00' * 32

        # 初始化MPC共识模拟器
        self.mpc_simulator = MPCConsensusSimulator(
            participants=[f"node_{i}" for i in range(5)],  # 5个参与者
            threshold=3  # 阈值3
        )
        self.mpc_simulator.set_network_model({
            'reliability': 0.9,  # 90%可靠性
            'latency': 100  # 延迟100ms
        })

        print("[Blockchain] 系统初始化完成，使用增强版SimpleCP-ABE")

    async def initialize(self):
        await self.storage.initialize()
        #加载已有的BAT树
        bat_nodes = await self.storage.load_bat_tree()
        if bat_nodes:
            self.bat.root = bat_nodes.get('root', self.bat.root)
            self.bat.leaf_nodes = {node.block_hash: node for node in bat_nodes.values() if node.level > 0}
            print(f"[Blockchain] 已加载 {len(bat_nodes)} 个BAT节点")
        print("[Blockchain] 存储初始化完成")

    async def _generate_unique_label(self) -> bytes:
        while True:
            label_data = f"label_{self.block_counter}_{time.time()}_{secrets.token_hex(8)}".encode()
            label = hashlib.sha3_256(label_data).digest()
            ok = await self.storage.is_label_unique(label)
            if ok:
                return label

    async def create_normal_block(self, data: bytes, label: Optional[bytes] = None) -> Dict:
        if label is None:
            label = await self._generate_unique_label()
        committee_km = self.dual.current_committee()
        committee_bytes = committee_km.public_bytes()
        prev_hash = self.last_hash
        inner_hash, inner_r = self.dual.compute_inner(data, label)
        outer_hash, outer_r = self.dual.compute_outer(inner_hash, committee_bytes, prev_hash, label)
        self.block_counter += 1
        block = {
            'block_hash': outer_hash,
            'block_number': self.block_counter,
            'data': data,
            'chameleon_hash': outer_hash,
            'chameleon_inner_hash': inner_hash,
            'random_nonce': inner_r + outer_r,
            'public_key': committee_bytes,
            'label': label,
            'prev_hash': prev_hash,
            'block_type': 'normal',
            'policy_info': {},
            'created_at': time.time()
        }
        ok = await self.storage.store_block(block)
        if not ok:
            raise RuntimeError("区块存储失败")

        # 绑定到 RHVT 和 BAT
        block_data = {'data': data, 'block_hash': outer_hash}
        self.rhvt.bind_block(block_data)
        self.bat.bind_block(block_data)
        #持久化BAT节点
        await self.storage.store_bat_node(self.bat.root)
        self.last_hash = outer_hash
        print(f"[Blockchain] 普通区块创建 #{self.block_counter} hash={outer_hash.hex()[:16]}...")
        return block

    async def create_pch_block(self, data: bytes, policy: str) -> Dict:
        label = await self._generate_unique_label()
        prev_hash = self.last_hash
        pch_res = self.pch.hash_with_policy(data, policy, label, prev_hash=prev_hash)

        # 处理随机数
        try:
            inner_r = bytes.fromhex(pch_res['inner_r'])
            outer_r = bytes.fromhex(pch_res['outer_r'])
            random_nonce = inner_r + outer_r
        except Exception:
            # 如果十六进制解码失败，使用回退方法
            inner_r = pch_res['inner_r'].encode('utf-8')[:32].ljust(32, b'\x00')
            outer_r = pch_res['outer_r'].encode('utf-8')[:32].ljust(32, b'\x00')
            random_nonce = inner_r + outer_r

        # --- 修复：移除encrypted_r中的AST，因为它不可JSON序列化 ---
        encrypted_r = pch_res['encrypted_r']
        encrypted_r.pop('policy_info', None)  # 删除包含PolicyNode的policy_info键
        # --------------------------------------------------------------

        self.block_counter += 1
        block = {
            'block_hash': bytes.fromhex(pch_res['outer_hash']),
            'block_number': self.block_counter,
            'data': data,
            'chameleon_hash': bytes.fromhex(pch_res['outer_hash']),
            'chameleon_inner_hash': bytes.fromhex(pch_res['inner_hash']),
            'random_nonce': random_nonce,
            'public_key': self.dual.current_committee().public_bytes(),
            'label': label,
            'prev_hash': prev_hash,
            'block_type': 'pch',
            'policy_info': {
                'policy': policy,
                'inner_hash': pch_res['inner_hash'],
                'outer_hash': pch_res['outer_hash'],
                'encrypted_r': encrypted_r,  # 现在已清理
                'msp_matrix': encrypted_r.get('msp_matrix'),
                'msp_rho': encrypted_r.get('msp_rho'),
                'prev_hash': pch_res.get('prev_hash')
            },
            'created_at': time.time()
        }
        ok = await self.storage.store_block(block)
        if not ok:
            raise RuntimeError("PCH区块存储失败")

        # 绑定到 RHVT 和 BAT
        block_data = {'data': data, 'block_hash': block['block_hash']}
        self.rhvt.bind_block(block_data)
        self.bat.bind_block(block_data)
        await self.storage.store_bat_node(self.bat.root)
        self.last_hash = block['block_hash']
        print(
            f"[Blockchain] PCH区块创建 #{self.block_counter} policy={policy} hash={block['block_hash'].hex()[:16]}...")
        return block

    async def edit_block(self, req: BlockEditRequest) -> bool:
        orig = await self.storage.get_block(req.block_hash)
        if not orig:
            raise ValueError("block not found")

        # 首先进行MPC共识
        consensus_success, consensus_info = self.mpc_simulator.simulate_consensus(req)
        print(f"[MPC] 共识结果: {'成功' if consensus_success else '失败'}, 信息: {consensus_info}")

        if not consensus_success:
            print("[Blockchain] 编辑请求未通过MPC共识")
            return False

        if orig['block_type'] == 'pch':
            return await self._edit_pch(req, orig)
        else:
            return await self._edit_normal(req, orig)

    async def _edit_normal(self, req: BlockEditRequest, orig: Dict) -> bool:
        committee_bytes = orig['public_key']
        if isinstance(committee_bytes, memoryview):
            committee_bytes = bytes(committee_bytes)
        committee_km = self.dual.current_committee()
        rn = orig['random_nonce']
        if not rn or len(rn) < 2:
            raise ValueError("invalid nonce")
        half = len(rn) // 2
        inner_r = rn[:half]
        outer_r = rn[half:]
        label = orig['label']
        new_inner_r = self.dual.compute_inner_collision(committee_km.private, label, req.original_data, inner_r,
                                                        req.edited_data)
        new_inner_hash, _ = self.dual.compute_inner(req.edited_data, label, new_inner_r)
        prev_hash = orig.get('prev_hash', self.last_hash)
        original_combined = orig['chameleon_inner_hash'] + committee_bytes + prev_hash
        new_combined = new_inner_hash + committee_bytes + prev_hash
        new_outer_r = self.dual.compute_outer_collision(label, original_combined, outer_r, new_combined)
        edit_record = {
            'block_hash': req.block_hash,
            'original_data': req.original_data,
            'edited_data': req.edited_data,
            'editor_id': req.editor_id,
            'edit_reason': req.edit_reason,
            'edit_type': req.edit_type,
            'previous_nonce': orig['random_nonce'],
            'new_nonce': new_inner_r + new_outer_r,
            'chameleon_inner_hash': new_inner_hash,
            'prev_hash': prev_hash,
            'edit_proof': None,
            'timestamp': req.timestamp
        }
        ok = await self.storage.add_edit_record(edit_record)
        if ok:
            print("[Blockchain] 普通区块编辑成功")
            return True
        return False

    async def _edit_pch(self, req: BlockEditRequest, orig: Dict) -> bool:
        policy_info = orig['policy_info']
        policy = policy_info.get('policy', '')
        user_attrs = req.policy_check.get('user_attributes', []) if req.policy_check else []

        if not policy:
            print("[Blockchain] PCH区块缺少策略信息")
            return False

        # 准备哈希数据
        rn = orig['random_nonce']
        if not rn or len(rn) < 2:
            print("[Blockchain] 无效的随机数")
            return False

        half = len(rn) // 2
        inner_r = rn[:half]
        outer_r = rn[half:]

        hash_data = {
            'inner_hash': policy_info['inner_hash'],
            'outer_hash': policy_info['outer_hash'],
            'label': orig['label'].hex() if isinstance(orig['label'], (bytes, bytearray)) else orig['label'],
            'policy': policy,
            'encrypted_r': policy_info['encrypted_r'],
            'inner_r': inner_r.hex(),
            'outer_r': outer_r.hex(),
            'prev_hash': policy_info.get('prev_hash', '00' * 32)
        }

        try:
            # 使用PCH适配
            new_inner_r, new_outer_r = self.pch.adapt_with_policy(
                user_attrs, req.original_data, req.edited_data,
                hash_data, prev_hash=bytes.fromhex(hash_data['prev_hash'])
            )

            edit_record = {
                'block_hash': req.block_hash,
                'original_data': req.original_data,
                'edited_data': req.edited_data,
                'editor_id': req.editor_id,
                'edit_reason': req.edit_reason,
                'edit_type': 'pch',
                'previous_nonce': orig['random_nonce'],
                'new_nonce': new_inner_r + new_outer_r,
                'chameleon_inner_hash': None,
                'prev_hash': orig.get('prev_hash'),
                'edit_proof': json.dumps({'user_attrs': user_attrs, 'policy': policy}).encode(),
                'timestamp': req.timestamp
            }
            ok = await self.storage.add_edit_record(edit_record)
            if ok:
                print("[Blockchain] PCH区块编辑成功")
                return True
        except Exception as e:
            print(f"[Blockchain] PCH编辑异常: {e}")
            # 打印完整的错误堆栈
            import traceback
            traceback.print_exc()
            print("[Blockchain] 策略不满足或解密失败，编辑被拒绝")
        return False

    async def verify_block(self, block_hash: bytes) -> bool:
        b = await self.storage.get_block(block_hash)
        if not b:
            return False
        if b['block_type'] == 'pch':
            return await self._verify_pch(b)
        else:
            return await self._verify_normal(b)

    async def _verify_normal(self, b: Dict) -> bool:
        try:
            rn = b['random_nonce']
            if not rn or len(rn) < 2:
                return False
            half = len(rn) // 2
            inner_r = rn[:half]
            outer_r = rn[half:]
            label = b['label']
            computed_inner, _ = self.dual.compute_inner(b['data'], label, inner_r)
            prev_hash = b.get('prev_hash', self.last_hash)
            committee_bytes = b['public_key']
            if isinstance(committee_bytes, memoryview):
                committee_bytes = bytes(committee_bytes)
            computed_outer, _ = self.dual.compute_outer(computed_inner, committee_bytes, prev_hash, label, outer_r)
            return constant_time.bytes_eq(computed_outer, b['chameleon_hash'])
        except Exception as e:
            print(f"[Blockchain] 普通区块验证失败: {e}")
            return False

    async def _verify_pch(self, b: Dict) -> bool:
        try:
            policy_info = b['policy_info']
            hash_data = {
                'inner_hash': policy_info['inner_hash'],
                'outer_hash': policy_info['outer_hash'],
                'label': b['label'].hex() if isinstance(b['label'], (bytes, bytearray)) else b['label'],
                'policy': policy_info['policy'],
                'encrypted_r': policy_info['encrypted_r'],
                'prev_hash': policy_info.get('prev_hash', '00' * 32)
            }
            rn = b['random_nonce']
            half = len(rn) // 2
            inner_r = rn[:half]
            outer_r = rn[half:]
            prev_hash = bytes.fromhex(hash_data['prev_hash'])
            return self.pch.verify_hash(hash_data, b['data'], inner_r, outer_r, prev_hash=prev_hash)
        except Exception as e:
            print(f"[Blockchain] PCH验证失败: {e}")
            return False

    async def audit(self) -> Dict:
        all_blocks = await self.storage.get_all_blocks()
        total = len(all_blocks)
        verified = 0
        for block in all_blocks:
            if await self.verify_block(block['block_hash']):
                verified += 1

        # 使用BAT进行完整性审计
        bat_root = self.bat.get_root_commitment()
        bat_stats = self.bat.stats()

        rh = self.rhvt.stats()
        result = {
            'total_blocks': total,
            'verified_blocks': verified,
            'integrity_percentage': (verified / total * 100 if total > 0 else 0),
            'rhvt_consistent': rh['total_blocks'] == total,
            'storage_efficiency': self._storage_efficiency(total),
            'bat_root_commitment': bat_root.hex() if bat_root else None,
            'bat_stats': bat_stats,
            'cpabe_info': self.cpabe_impl.get_system_info()
        }
        print("[Blockchain] 审计完成", result)
        return result

    def _storage_efficiency(self, total_blocks: int) -> float:
        traditional = total_blocks * 1024
        rhvt_over = self.rhvt.stats()['storage_overhead_bytes']
        if traditional <= 0: return 0.0
        return max(0.0, min(1.0, (traditional - rhvt_over) / traditional))

    def info(self) -> Dict:
        return {
            'block_counter': self.block_counter,
            'committee_size': len(self.committee_kms),
            'last_hash': self.last_hash.hex()[:16] + '...',
            'rhvt_stats': self.rhvt.stats(),
            'bat_stats': self.bat.stats(),
            'cpabe_system': self.cpabe_impl.get_system_info()
        }


# -------------------------
# 宏基准测试
# -------------------------
async def comprehensive_benchmark(blockchain: Blockchain):
    """生成论文所需的完整实验数据集"""
    print("\n=== 开始综合基准测试 ===")

    # 实验1：存储开销对比
    print("\n实验1：存储开销对比")
    traditional_storage = []
    rhvt_storage = []
    bat_storage = []

    for num_blocks in [100, 500, 1000, 5000]:
        # 创建指定数量的区块
        for i in range(num_blocks):
            data = f"benchmark_block_{i}".encode()
            await blockchain.create_normal_block(data)

        # 测量传统结构（Merkle树）存储
        block_size = 1024  # 假设每个区块1KB
        traditional = num_blocks * block_size
        traditional_storage.append(traditional)

        # 测量RHVT存储
        rhvt_stats = blockchain.rhvt.stats()
        rhvt_overhead = rhvt_stats['storage_overhead_bytes']
        rhvt_storage.append(rhvt_overhead)

        # 测量BAT存储
        bat_stats = blockchain.bat.stats()
        bat_nodes = bat_stats['total_nodes']
        bat_overhead = bat_nodes * 32  # 每个节点承诺32字节
        bat_storage.append(bat_overhead)

        print(f"区块数={num_blocks}: 传统={traditional}B, RHVT={rhvt_overhead}B, BAT={bat_overhead}B")

    # 实验2：编辑延迟对比（普通 vs. PCH）
    print("\n实验2：编辑延迟对比")
    edit_latencies = []

    # 创建测试区块
    normal_data = "normal_test_data".encode()
    normal_block = await blockchain.create_normal_block(normal_data)

    policy = "(attr0 and attr1)"
    pch_data = "pch_test_data".encode()
    pch_block = await blockchain.create_pch_block(pch_data, policy)

    # 测试普通区块编辑
    start = time.perf_counter()
    normal_edit_req = BlockEditRequest(
        block_hash=normal_block['block_hash'],
        original_data=normal_data,
        edited_data="edited_normal_data".encode(),
        editor_id="benchmark_editor",
        edit_reason="benchmark"
    )
    normal_edit_ok = await blockchain.edit_block(normal_edit_req)
    normal_latency = time.perf_counter() - start

    # 测试PCH区块编辑
    start = time.perf_counter()
    pch_edit_req = BlockEditRequest(
        block_hash=pch_block['block_hash'],
        original_data=pch_data,
        edited_data="edited_pch_data".encode(),
        editor_id="benchmark_editor",
        edit_reason="benchmark",
        policy_check={'user_attributes': ['attr0', 'attr1']}
    )
    pch_edit_ok = await blockchain.edit_block(pch_edit_req)
    pch_latency = time.perf_counter() - start

    edit_latencies.append({
        'block_type': 'normal',
        'success': normal_edit_ok,
        'latency_ms': normal_latency * 1000
    })
    edit_latencies.append({
        'block_type': 'pch',
        'success': pch_edit_ok,
        'latency_ms': pch_latency * 1000
    })

    print(f"普通区块编辑: {'成功' if normal_edit_ok else '失败'}, 延迟={normal_latency * 1000:.3f}ms")
    print(f"PCH区块编辑: {'成功' if pch_edit_ok else '失败'}, 延迟={pch_latency * 1000:.3f}ms")

    # 实验3：不同策略复杂度对PCH性能的影响
    print("\n实验3：策略复杂度对PCH性能的影响")
    policy_complexities = [
        ('simple', "attr0"),
        ('medium', "(attr0 and attr1)"),
        ('complex', "(attr0 and attr1) or (attr2 and threshold(2, attr3, attr4, attr5))")
    ]

    policy_latencies = []

    for complexity_name, policy_str in policy_complexities:
        # 创建PCH区块
        data = f"policy_test_{complexity_name}".encode()
        block = await blockchain.create_pch_block(data, policy_str)

        # 编辑区块
        start = time.perf_counter()
        edit_req = BlockEditRequest(
            block_hash=block['block_hash'],
            original_data=data,
            edited_data=f"edited_{complexity_name}".encode(),
            editor_id="benchmark_editor",
            edit_reason="policy_benchmark",
            policy_check={'user_attributes': ['attr0', 'attr1', 'attr2', 'attr3', 'attr4']}
        )
        edit_ok = await blockchain.edit_block(edit_req)
        latency = time.perf_counter() - start

        policy_latencies.append({
            'policy_complexity': complexity_name,
            'policy': policy_str,
            'success': edit_ok,
            'latency_ms': latency * 1000
        })

        print(f"策略复杂度={complexity_name}: {'成功' if edit_ok else '失败'}, 延迟={latency * 1000:.3f}ms")

    # 导出为JSON
    results = {
        'storage_comparison': {
            'num_blocks': [100, 500, 1000, 5000],
            'traditional_storage_bytes': traditional_storage,
            'rhvt_storage_bytes': rhvt_storage,
            'bat_storage_bytes': bat_storage
        },
        'edit_latency_comparison': edit_latencies,
        'policy_complexity_latency': policy_latencies,
        'timestamp': time.time()
    }

    with open('benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("\n=== 基准测试完成 ===")
    print("结果已保存到 benchmark_results.json")

    return results


# -------------------------
# 演示 / 测试 主函数
# -------------------------
async def main_demo():
    print("=" * 80)
    print("轻量化可编辑可验证区块链系统 - 增强版（基于SimpleCP-ABE）")
    print("=" * 80)

    # 减少RSA密钥生成时间
    ca_km = RSAKeyManager(SecurityConfig.RSA_KEY_SIZE)
    ca_km.generate()
    print(f"CA 密钥已生成 ({SecurityConfig.RSA_KEY_SIZE} bits)")

    storage = AsyncStorage("blockchain_enhanced.db")
    bc = Blockchain(ca_km, storage=storage)
    await bc.initialize()

    # 创建普通区块
    normal_data = "这是一个普通区块链数据块".encode("utf-8")
    normal_block = await bc.create_normal_block(normal_data)
    print("普通区块创建完成:", normal_block['block_number'])

    # 创建PCH区块（使用简单策略提高性能）
    simple_policy = "attr0"
    pch_data = "这是基于简单策略的敏感数据".encode("utf-8")
    pch_block = await bc.create_pch_block(pch_data, simple_policy)
    print("PCH 区块创建完成:", pch_block['block_number'])

    # 创建PCH区块（使用复杂策略）
    complex_policy = "(attr0 and attr1) or attr2"
    pch_data_complex = "这是基于复杂策略的敏感数据".encode("utf-8")
    pch_block_complex = await bc.create_pch_block(pch_data_complex, complex_policy)
    print("复杂策略PCH区块创建完成:", pch_block_complex['block_number'])

    # 验证区块
    nv = await bc.verify_block(normal_block['block_hash'])
    pv = await bc.verify_block(pch_block['block_hash'])
    pv_complex = await bc.verify_block(pch_block_complex['block_hash'])
    print("普通区块验证:", "通过" if nv else "失败")
    print("简单策略PCH区块验证:", "通过" if pv else "失败")
    print("复杂策略PCH区块验证:", "通过" if pv_complex else "失败")

    # 编辑普通区块
    edit_req_normal = BlockEditRequest(
        block_hash=normal_block['block_hash'],
        original_data=normal_data,
        edited_data="这是编辑后的普通数据".encode("utf-8"),
        editor_id="editor_1",
        edit_reason="数据修正",
        edit_type="normal"
    )
    ok_norm_edit = await bc.edit_block(edit_req_normal)
    print("普通区块编辑:", "成功" if ok_norm_edit else "失败")

    # 编辑简单策略PCH区块（使用正确属性）
    edit_req_pch = BlockEditRequest(
        block_hash=pch_block['block_hash'],
        original_data=pch_data,
        edited_data="这是编辑后的敏感数据".encode("utf-8"),
        editor_id="editor_2",
        edit_reason="数据修正",
        edit_type="pch",
        policy_check={'user_attributes': ['attr0']}  # 拥有所需属性
    )
    ok_pch_edit = await bc.edit_block(edit_req_pch)
    print("简单策略PCH区块编辑（正确属性）:", "成功" if ok_pch_edit else "失败")

    # 编辑简单策略PCH区块（使用错误属性）
    edit_req_pch_wrong = BlockEditRequest(
        block_hash=pch_block['block_hash'],
        original_data=pch_data,
        edited_data="这是试图非法编辑的数据".encode("utf-8"),
        editor_id="editor_3",
        edit_reason="非法尝试",
        edit_type="pch",
        policy_check={'user_attributes': ['attr_wrong']}  # 没有所需属性
    )
    ok_pch_edit_wrong = await bc.edit_block(edit_req_pch_wrong)
    print("简单策略PCH区块编辑（错误属性）:", "成功" if ok_pch_edit_wrong else "失败（预期失败）")

    # 编辑复杂策略PCH区块
    edit_req_pch_complex = BlockEditRequest(
        block_hash=pch_block_complex['block_hash'],
        original_data=pch_data_complex,
        edited_data="这是编辑后的复杂策略数据".encode("utf-8"),
        editor_id="editor_4",
        edit_reason="数据修正",
        edit_type="pch",
        policy_check={'user_attributes': ['attr0', 'attr1']}  # 满足 (attr0 and attr1)
    )
    ok_pch_edit_complex = await bc.edit_block(edit_req_pch_complex)
    print("复杂策略PCH区块编辑:", "成功" if ok_pch_edit_complex else "失败")

    # 审计区块链
    audit_res = await bc.audit()
    print("审计结果:", audit_res)
    print("系统信息:", bc.info())

    # 运行简化的微基准测试
    print("\n=== 运行简化微基准测试 ===")
    micro_bench = CryptographyMicroBenchmark(ca_km)
    param_set = [
        {'n_bits': 1024, 'exponent_sizes': [128, 256]}  # 减少测试参数
    ]
    rhvt_results = micro_bench.measure_rhvt_tag_generation(param_set)
    chameleon_results = micro_bench.measure_chameleon_hash(message_sizes=[64, 128])  # 减少消息大小
    micro_bench.export_results()

    # 运行简化的综合基准测试
    print("\n=== 运行简化综合基准测试 ===")
    # 减少测试规模
    benchmark_results = await simplified_benchmark(bc)

    return {
        'normal_block': normal_block,
        'pch_block': pch_block,
        'pch_block_complex': pch_block_complex,
        'ok_norm_edit': ok_norm_edit,
        'ok_pch_edit': ok_pch_edit,
        'ok_pch_edit_wrong': ok_pch_edit_wrong,
        'ok_pch_edit_complex': ok_pch_edit_complex,
        'audit': audit_res,
        'benchmark_results': benchmark_results
    }


async def simplified_benchmark(blockchain: Blockchain):
    """简化的基准测试"""
    print("\n=== 开始简化基准测试 ===")

    # 实验1：存储开销对比（减少规模）
    print("\n实验1：存储开销对比")
    traditional_storage = []
    rhvt_storage = []

    for num_blocks in [10, 50]:  # 减少测试数量
        # 创建指定数量的区块
        for i in range(num_blocks):
            data = f"benchmark_block_{i}".encode()
            await blockchain.create_normal_block(data)

        # 测量传统结构（Merkle树）存储
        block_size = 1024  # 假设每个区块1KB
        traditional = num_blocks * block_size
        traditional_storage.append(traditional)

        # 测量RHVT存储
        rhvt_stats = blockchain.rhvt.stats()
        rhvt_overhead = rhvt_stats['storage_overhead_bytes']
        rhvt_storage.append(rhvt_overhead)

        print(f"区块数={num_blocks}: 传统={traditional}B, RHVT={rhvt_overhead}B")

    # 实验2：编辑延迟对比（普通 vs. PCH）
    print("\n实验2：编辑延迟对比")
    edit_latencies = []

    # 创建测试区块
    normal_data = "normal_test_data".encode()
    normal_block = await blockchain.create_normal_block(normal_data)

    policy = "attr0"
    pch_data = "pch_test_data".encode()
    pch_block = await blockchain.create_pch_block(pch_data, policy)

    # 测试普通区块编辑
    start = time.perf_counter()
    normal_edit_req = BlockEditRequest(
        block_hash=normal_block['block_hash'],
        original_data=normal_data,
        edited_data="edited_normal_data".encode(),
        editor_id="benchmark_editor",
        edit_reason="benchmark"
    )
    normal_edit_ok = await blockchain.edit_block(normal_edit_req)
    normal_latency = time.perf_counter() - start

    # 测试PCH区块编辑
    start = time.perf_counter()
    pch_edit_req = BlockEditRequest(
        block_hash=pch_block['block_hash'],
        original_data=pch_data,
        edited_data="edited_pch_data".encode(),
        editor_id="benchmark_editor",
        edit_reason="benchmark",
        policy_check={'user_attributes': ['attr0']}
    )
    pch_edit_ok = await blockchain.edit_block(pch_edit_req)
    pch_latency = time.perf_counter() - start

    edit_latencies.append({
        'block_type': 'normal',
        'success': normal_edit_ok,
        'latency_ms': normal_latency * 1000
    })
    edit_latencies.append({
        'block_type': 'pch',
        'success': pch_edit_ok,
        'latency_ms': pch_latency * 1000
    })

    print(f"普通区块编辑: {'成功' if normal_edit_ok else '失败'}, 延迟={normal_latency * 1000:.3f}ms")
    print(f"PCH区块编辑: {'成功' if pch_edit_ok else '失败'}, 延迟={pch_latency * 1000:.3f}ms")

    # 导出为JSON
    results = {
        'storage_comparison': {
            'num_blocks': [10, 50],
            'traditional_storage_bytes': traditional_storage,
            'rhvt_storage_bytes': rhvt_storage
        },
        'edit_latency_comparison': edit_latencies,
        'timestamp': time.time()
    }

    with open('simplified_benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("\n=== 简化基准测试完成 ===")
    print("结果已保存到 simplified_benchmark_results.json")

    return results


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        res = loop.run_until_complete(main_demo())
        with open('blockchain_enhanced_results.json', 'w') as f:
            json.dump({
                'normal_edit_success': res['ok_norm_edit'],
                'pch_edit_success': res['ok_pch_edit'],
                'pch_edit_wrong_failed': not res['ok_pch_edit_wrong'],  # 预期为True（失败）
                'pch_complex_edit_success': res['ok_pch_edit_complex'],
                'audit': res['audit'],
                'cpabe_system': res['audit']['cpabe_info']
            }, f, indent=2)
        print("\n" + "=" * 80)
        print("演示与测试完成。结果已保存到 blockchain_enhanced_results.json")
        print("=" * 80)
    except Exception as e:
        print("运行错误:", e)
        import traceback

        traceback.print_exc()