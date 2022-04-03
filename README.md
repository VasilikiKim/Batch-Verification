# Batch-Verification
ECDSA Batch Verification
##目录结构
Batch-Verification-main\
├── BitECDSA.iml\
├── README.md\
├── jar\
│   ├── bcprov-ext-jdk15to18-166.jar\
│   └── bcprov-jdk15to18-166.jar\
├── pom.xml\
├── src\
│   └── main\
│       └── java\
│           ├── ECDSA.java\   
│           ├── GenerateKey.java\
│           ├── PointMultiplication.java\
│           ├── TonelliShanks.java\
│           └── test.java\
└── target\
    └── classes\
        ├── ECDSA.class\
        ├── GenerateKey.class\
        ├── PointMultiplication.class\
        ├── TonelliShanks$Solution.class\
        ├── TonelliShanks.class\
        └── test.class\
## 论文地址
<https://ieeexplore.ieee.org/abstract/document/9540329>
##说明
-1.椭圆曲线求根运算参照TonelliShanks算法

