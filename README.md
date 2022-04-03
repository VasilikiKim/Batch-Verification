# Batch-Verification
- 1.给出了椭圆曲线批验证方案实现与相关方案对比
- 2.给出了组测试方案与批验证结合实现
- 3.椭圆曲线求根运算参照TonelliShanks算法

## 目录结构
```
Batch-Verification-main
├── BitECDSA.iml   
├── README.md   
├── jar 
│   ├── bcprov-ext-jdk15to18-166.jar 
│   └── bcprov-jdk15to18-166.jar 
├── pom.xml
├── src
│   └── main
│       └── java
│           ├── ECDSA.java
│           ├── GenerateKey.java
│           ├── PointMultiplication.java
│           ├── TonelliShanks.java
│           └── test.java
└── target
    └── classes
        ├── ECDSA.class
        ├── GenerateKey.class
        ├── PointMultiplication.class
        ├── TonelliShanks$Solution.class
        ├── TonelliShanks.class
        └── test.class
```
        
## 论文地址
<https://ieeexplore.ieee.org/abstract/document/9540329>



