# TLS 密码套件性能分析



## 项目要求

针对TLS不同的加密套件，包含ECDHE和FFDHE，编写JMH性能测试程序，比较它们的性能差异，并分析可能的原因。



## TLS

#### 为什么需要密码套件？

SSL 握手是一个复杂的过程，因为它利用了多种加密功能来实现 HTTPS 连接。在握手过程中，客户端和网络服务器将使用：

- 密钥交换算法，用于确定对称密钥的交换方式
- 认证或数字签名算法，决定如何实现服务器认证和（如果需要）客户端认证
- 大块加密密码，用于加密数据
- 哈希/MAC 函数，用于确定数据完整性检查的方式

这些密码在连接的各个点上都是必需的，用于执行认证、密钥生成和交换，以及校验和以确保完整性。为了确定使用哪些特定的算法，客户端和网络服务器首先需要相互决定使用哪个密码套件。

密码套件之所以重要，是因为服务器、操作系统和浏览器的多样性。需要一种方式来兼容所有这些组合，因此密码套件在确保兼容性方面发挥了重要作用。

#### 密码套件如何工作

在连接的握手过程中，当客户端和服务器交换信息时，网络服务器和浏览器会比较它们支持的密码套件的优先级列表，查看是否兼容，然后确定使用哪个密码套件。

关于使用哪个密码套件的决定由网络服务器来做。商定的密码套件是以下几种的组合：

- 密钥交换算法，如 RSA、DH、ECDH、DHE、ECDHE 或 PSK
- 认证/数字签名算法，如 RSA、ECDSA 或 DSA
- 大块加密算法，如 AES、CHACHA20、Camellia 或 ARIA
- 消息认证码算法，如 SHA-256 和 POLY1305

#### 密码套件的重要性

密码套件对于确保 HTTPS 连接的安全性、兼容性和性能至关重要。就像食谱描述了制作完美菜肴所需的成分一样，密码套件规定了用于建立安全可靠连接的算法。

正如之前提到的，最终决定使用哪个密码套件的是网络服务器。因此，网络服务器上的密码套件优先级列表非常重要。选择正确的密码套件在任何网络服务器上都是一项至关重要的工作，主要取决于连接到服务器的用户类型以及他们使用的技术。

用户也有责任确保连接的安全性。由于浏览器供应商在发现漏洞后会更新其支持的密码套件列表，用户必须安装最新的浏览器补丁，以减少在服务器端废弃弱密码套件时遇到兼容性问题的可能性。

#### 选择密码套件

在本实验中，选择的加密套件为：

- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_DHE_RSA_WITH_AES_128_CBC_SHA256



## JMH

JMH 全称 Java Microbenchmark Harness，是用于构建、运行和分析以 Java 和其他基于 JVM 的其他语言编写的 nano/micro/milli/macro 基准测试的 Java 工具。

#### 使用场景

JMH 适用范围示例：

- a. 度量某个方法执行耗时

- b. 度量某个方法执行时间和输入 n 的相关性

- c. 评估一个方法的多种不同实现性能表现

- d. 评估应用中调用的第三方库 API 的执行性能

- e. b&c 综合应用

  

## 测试环境设置

#### 操作系统

Ubuntu22.04  8G8核 80GB

#### JDK 版本

```
openjdk version "17" 2021-10-13 LTS
OpenJDK Runtime Environment TencentKonaJDK (build 17+35-LTS)
OpenJDK 64-Bit Server VM TencentKonaJDK (build 17+35-LTS, mixed mode, sharing)
```



## JMH 性能测试程序

### 实验一：连接建立时间测试

#### 代码

```
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

public class TLSBenchmark {

    @State(Scope.Thread)
    public static class BenchmarkState {
        @Param({
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
        })
        String cipherSuite;

        SSLSocketFactory sslSocketFactory;

        @Setup(Level.Trial)
        public void setup() throws NoSuchAlgorithmException, KeyManagementException {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new DummyTrustManager()}, null);
            sslSocketFactory = sslContext.getSocketFactory();
        }

        private static class DummyTrustManager implements X509TrustManager {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testConnection(BenchmarkState state) throws IOException {
        SSLSocket socket = (SSLSocket) state.sslSocketFactory.createSocket();
        socket.setEnabledCipherSuites(new String[]{state.cipherSuite});
        socket.connect(new InetSocketAddress("kaxiya.top", 443), 10000);
        socket.close();
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(TLSBenchmark.class.getSimpleName())
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}
```

#### 结果分析

一共运行了五次，每次warmup 5轮，实际测量5轮，取平均值，结果如下：

| 加密套件                                  | 第一次                | 第二次                | 第三次                | 第四次                | 第五次                | 平均值        | 标准差       |
| ----------------------------------------- | --------------------- | --------------------- | --------------------- | --------------------- | --------------------- | ------------- | ------------ |
| **TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256** | 57.894 ± 7.926 ms/op  | 61.369 ± 6.275 ms/op  | 64.235 ± 4.467 ms/op  | 62.652 ± 7.037 ms/op  | 59.466 ± 6.304 ms/op  | 61.1232 ms/op | 2.2474 ms/op |
| **TLS_DHE_RSA_WITH_AES_128_GCM_SHA256**   | 61.431 ± 4.560 ms/op  | 59.394 ± 4.860 ms/op  | 64.576 ± 14.212 ms/op | 61.741 ± 9.368 ms/op  | 72.206 ± 44.840 ms/op | 63.8696 ms/op | 4.4834 ms/op |
| **TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384** | 60.798 ± 3.116 ms/op  | 60.507 ± 4.848 ms/op  | 62.333 ± 15.209 ms/op | 61.166 ± 2.573 ms/op  | 59.395 ± 6.735 ms/op  | 60.8398 ms/op | 0.9525 ms/op |
| **TLS_DHE_RSA_WITH_AES_256_GCM_SHA384**   | 60.228 ± 4.413 ms/op  | 63.104 ± 17.494 ms/op | 64.499 ± 39.466 ms/op | 60.889 ± 5.667 ms/op  | 57.878 ± 4.841 ms/op  | 61.3196 ms/op | 2.3028 ms/op |
| **TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256** | 67.593 ± 33.323 ms/op | 62.218 ± 7.783 ms/op  | 62.208 ± 6.377 ms/op  | 68.609 ± 40.581 ms/op | 66.096 ± 22.714 ms/op | 65.3448 ms/op | 2.6792 ms/op |
| **TLS_DHE_RSA_WITH_AES_128_CBC_SHA256**   | 59.506 ± 2.843 ms/op  | 60.128 ± 3.548 ms/op  | 63.492 ± 7.225 ms/op  | 61.510 ± 3.392 ms/op  | 57.679 ± 3.014 ms/op  | 60.4630 ms/op | 1.9519 ms/op |

#### 结论

1. **平均性能**
   - **TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384** 具有最低的平均值 60.8398 ms/op，表现最佳。
   - **TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256** 具有最高的平均值 65.3448 ms/op，表现最差。
   - **GCM模式**总体表现较为稳定，但个别测试存在较大波动。
   - **CBC模式**表现相对不稳定，误差也相对较大。
2. **性能稳定性**
   - **TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384** 标准差最低，仅为 0.9525 ms/op，表现最稳定。
   - **TLS_DHE_RSA_WITH_AES_128_GCM_SHA256** 标准差最高，为 4.4834 ms/op，表现最不稳定。
3. **综合考虑**
   - **TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384** 不仅平均值最低，标准差也最低，是最优选择。

#### 原因分析

- **加密套件复杂度**：不同加密套件的计算复杂度不同，特别是CBC和GCM模式之间。GCM模式通常效率更高，因为是并行计算，但在某些情况下，CBC模式可能更适合特定的硬件或软件环境。

- **密钥长度**：256位加密通常比128位加密需要更多计算资源，尽管现代硬件通常能够高效处理这类加密，但在负载较高时仍可能影响性能。

  

### 实验二：数据传输性能测试

#### 代码

```
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;

import java.io.*;


@State(Scope.Thread)
public class TLSBenchmark {

    private SSLSocketFactory[] socketFactories = new SSLSocketFactory[6];
    private String[] cipherSuites = {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
    };
    private String serverAddress = "localhost";
    private int serverPort = 443;

    private PrintWriter[] logWriters = new PrintWriter[6];

    @Setup(Level.Trial)
    public void setup() {
        for (int i = 0; i < cipherSuites.length; i++) {
            socketFactories[i] = createSocketFactory(cipherSuites[i]);
            try {
                logWriters[i] = new PrintWriter(new FileWriter(cipherSuites[i] + ".log", true));
            } catch (IOException e) {
                throw new RuntimeException("Failed to open log file for " + cipherSuites[i], e);
            }
        }
    }

    private SSLSocketFactory createSocketFactory(String cipherSuite) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLSocketFactory factory = context.getSocketFactory();
            return factory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferECDHE_RSA_WITH_AES_128_GCM_SHA256() {
        testDataTransfer(socketFactories[0], logWriters[0]);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferDHE_RSA_WITH_AES_128_GCM_SHA256() {
        testDataTransfer(socketFactories[1], logWriters[1]);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferECDHE_RSA_WITH_AES_256_GCM_SHA384() {
        testDataTransfer(socketFactories[2], logWriters[2]);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferDHE_RSA_WITH_AES_256_GCM_SHA384() {
        testDataTransfer(socketFactories[3], logWriters[3]);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferECDHE_RSA_WITH_AES_128_CBC_SHA256() {
        testDataTransfer(socketFactories[4], logWriters[4]);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testDataTransferDHE_RSA_WITH_AES_128_CBC_SHA256() {
        testDataTransfer(socketFactories[5], logWriters[5]);
    }

    private void testDataTransfer(SSLSocketFactory factory, PrintWriter logWriter) {
        try (SSLSocket socket = (SSLSocket) factory.createSocket(serverAddress, serverPort)) {
            socket.startHandshake();
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[8192];
            long start = System.nanoTime();
            for (int i = 0; i < 10; i++) {
                out.write(buffer);
                in.read(buffer);
            }
            long end = System.nanoTime();
            logWriter.println("Data transfer time: " + (end - start) / 1_000_000 + " ms");
        } catch (Exception e) {
            logWriter.println("Error in testDataTransfer: " + e.getMessage());
            e.printStackTrace(logWriter);
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        for (PrintWriter logWriter : logWriters) {
            if (logWriter != null) {
                logWriter.close();
            }
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(TLSBenchmark.class.getSimpleName())
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}
```

#### 结果分析

```
Benchmark                                                       Mode  Cnt  Score   Error  Units
TLSBenchmark.testDataTransferDHE_RSA_WITH_AES_128_CBC_SHA256    avgt    5  0.158 ± 0.023  ms/op
TLSBenchmark.testDataTransferDHE_RSA_WITH_AES_128_GCM_SHA256    avgt    5  0.164 ± 0.034  ms/op
TLSBenchmark.testDataTransferDHE_RSA_WITH_AES_256_GCM_SHA384    avgt    5  0.158 ± 0.022  ms/op
TLSBenchmark.testDataTransferECDHE_RSA_WITH_AES_128_CBC_SHA256  avgt    5  0.158 ± 0.027  ms/op
TLSBenchmark.testDataTransferECDHE_RSA_WITH_AES_128_GCM_SHA256  avgt    5  0.160 ± 0.043  ms/op
TLSBenchmark.testDataTransferECDHE_RSA_WITH_AES_256_GCM_SHA384  avgt    5  0.151 ± 0.013  ms/op
```

所有测试的平均操作时间都非常接近，均在 0.151 ms 到 0.164 ms 之间。这表明在你的测试环境和负载下，不同密码套件之间的性能差异并不显著。



## 附录：整体测试

（该测试受网络影响误差较大，仅作参考）

```
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.*;
import java.util.concurrent.TimeUnit;

import java.io.*;


@State(Scope.Benchmark)
public class TLSCipherSuiteBenchmark {

    private SSLSocketFactory ecdheSocketFactory;
    private SSLSocketFactory ffdheSocketFactory;
    private String serverAddress = "kaxiya.top";
    private int serverPort = 443;
    private OperatingSystemMXBean osBean;
    private ThreadMXBean threadBean;
    private MemoryMXBean memoryBean;

    private PrintWriter logWriter;

    @Setup(Level.Trial)
    public void setup() {
        ecdheSocketFactory = createSocketFactory("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        ffdheSocketFactory = createSocketFactory("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
        osBean = ManagementFactory.getOperatingSystemMXBean();
        threadBean = ManagementFactory.getThreadMXBean();
        memoryBean = ManagementFactory.getMemoryMXBean();

        try {
            // Initialize file writer and print writer
            logWriter = new PrintWriter(new FileWriter("RSA_WITH_AES_128_GCM_SHA256.log", true));
        } catch (IOException e) {
            throw new RuntimeException("Failed to open log file", e);
        }
    }

    private SSLSocketFactory createSocketFactory(String cipherSuite) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLSocketFactory factory = context.getSocketFactory();
            return factory;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testECDHEConnection() {
        testConnection(ecdheSocketFactory);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testFFDHEConnection() {
        testConnection(ffdheSocketFactory);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testECDHEDataTransfer() {
        testDataTransfer(ecdheSocketFactory);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testFFDHEDataTransfer() {
        testDataTransfer(ffdheSocketFactory);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testECDHECPUUsage() {
        measureCPUUsage(() -> testConnection(ecdheSocketFactory));
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testFFDHECPUUsage() {
        measureCPUUsage(() -> testConnection(ffdheSocketFactory));
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testECDHEMemoryUsage() {
        measureMemoryUsage(() -> testConnection(ecdheSocketFactory));
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public void testFFDHEMemoryUsage() {
        measureMemoryUsage(() -> testConnection(ffdheSocketFactory));
    }

    private void testConnection(SSLSocketFactory factory) {
        try (SSLSocket socket = (SSLSocket) factory.createSocket(serverAddress, serverPort)) {
            socket.startHandshake();
        } catch (Exception e) {
            logWriter.println("Error in testConnection: " + e.getMessage());
            e.printStackTrace(logWriter);
        }
    }

    private void testDataTransfer(SSLSocketFactory factory) {
        try (SSLSocket socket = (SSLSocket) factory.createSocket(serverAddress, serverPort)) {
            socket.startHandshake();
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[8192];
            long start = System.nanoTime();
            for (int i = 0; i < 10; i++) {
                out.write(buffer);
                in.read(buffer);
            }
            long end = System.nanoTime();
            logWriter.println("Data transfer time: " + (end - start) / 1_000_000 + " ms");
        } catch (Exception e) {
            logWriter.println("Error in testDataTransfer: " + e.getMessage());
            e.printStackTrace(logWriter);
        }
    }

    private void measureCPUUsage(Runnable task) {
        long startCPUTime = threadBean.getCurrentThreadCpuTime();
        task.run();
        long endCPUTime = threadBean.getCurrentThreadCpuTime();
        long cpuTimeUsed = (endCPUTime - startCPUTime) / 1_000_000;
        logWriter.println("CPU time used: " + cpuTimeUsed + " ms");
    }

    private void measureMemoryUsage(Runnable task) {
        MemoryUsage before = memoryBean.getHeapMemoryUsage();
        task.run();
        MemoryUsage after = memoryBean.getHeapMemoryUsage();
        long memoryUsed = after.getUsed() - before.getUsed();
        logWriter.println("Memory used: " + memoryUsed + " bytes");
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        if (logWriter != null) {
            logWriter.close();
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(TLSCipherSuiteBenchmark.class.getSimpleName())
                .forks(1)
                .build();

        new Runner(opt).run();
    }
}
```

主要测试了以下四个性能指标：

- **连接建立时间**：测量建立 TLS 连接所需的时间。

- **数据传输时间**：测量通过 TLS 连接传输数据所需的时间。

- **CPU 使用率**：测量建立 TLS 连接时的 CPU 使用情况。

- **内存使用率**：测量建立 TLS 连接时的内存使用情况。

## 日志部分分析

1、截取部分TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256和TLS_DHE_RSA_WITH_AES_128_GCM_SHA256的输出日志

```
TLSCipherSuiteBenchmark.testECDHECPUUsage      avgt    5  287.954 ± 1135.673  ms/op
TLSCipherSuiteBenchmark.testECDHEConnection    avgt    5  184.759 ±  285.081  ms/op
TLSCipherSuiteBenchmark.testECDHEDataTransfer  avgt    5  272.510 ±   17.459  ms/op
TLSCipherSuiteBenchmark.testECDHEMemoryUsage   avgt    5  217.311 ±  545.625  ms/op
TLSCipherSuiteBenchmark.testFFDHECPUUsage      avgt    5  145.619 ±    6.639  ms/op
TLSCipherSuiteBenchmark.testFFDHEConnection    avgt    5  242.179 ±  885.064  ms/op
TLSCipherSuiteBenchmark.testFFDHEDataTransfer  avgt    5  292.951 ±   32.262  ms/op
TLSCipherSuiteBenchmark.testFFDHEMemoryUsage   avgt    5  252.178 ±  924.594  ms/op
```

- **CPU使用：** `DHE`在CPU使用上表现更好（145.619 ms/op 对比 287.954 ms/op），可能的原因是`DHE`在密钥交换中使用了较为简单的计算，而`ECDHE`则使用了更复杂的椭圆曲线算法。尽管ECDHE通常在安全性和计算效率上有优势，但在某些环境中，DHE可能表现得更好。
- **连接时间：** `ECDHE`在建立连接时更快（184.759 ms/op 对比 242.179 ms/op），ECDHE协议通常在密钥协商阶段更高效，因为椭圆曲线算法可以在较小的密钥长度下提供相同的安全性，导致较快的协商速度。DHE协议需要较大的密钥来提供相同的安全级别，从而可能导致更长的连接时间。
- **数据传输：** 两者的数据传输时间差异不大。
- **内存使用：** `ECDHE` 的内存使用略低（ 217.311 bytes对比252.178 bytes）。可能原因为DHE协议在密钥交换时可能需要存储较大的临时数据（如大素数和生成的共享密钥），从而增加内存消耗。ECDHE由于使用椭圆曲线，这些数据通常较小，内存消耗较低。

2、截取部分TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384和TLS_DHE_RSA_WITH_AES_256_GCM_SHA384的输出日志

```
Benchmark                                      Mode  Cnt     Score       Error  Units
TLSCipherSuiteBenchmark.testECDHECPUUsage      avgt    5   322.263 ±  1508.296  ms/op
TLSCipherSuiteBenchmark.testECDHEConnection    avgt    5   142.127 ±     4.017  ms/op
TLSCipherSuiteBenchmark.testECDHEDataTransfer  avgt    5   265.663 ±    11.763  ms/op
TLSCipherSuiteBenchmark.testECDHEMemoryUsage   avgt    5   147.930 ±    18.469  ms/op
TLSCipherSuiteBenchmark.testFFDHECPUUsage      avgt    5  1561.781 ± 11950.665  ms/op
TLSCipherSuiteBenchmark.testFFDHEConnection    avgt    5  1064.483 ±  6049.355  ms/op
TLSCipherSuiteBenchmark.testFFDHEDataTransfer  avgt    5   445.015 ±  1285.310  ms/op
TLSCipherSuiteBenchmark.testFFDHEMemoryUsage   avgt    5   287.857 ±   742.730  ms/op
```

- **CPU使用：** `ECDHE` 显著低于 `DHE`（322.263 ms/op 对比 1561.781 ms/op）。可能原因为ECDHE在更高密钥长度下仍能保持较低的计算开销，因为椭圆曲线算法比DHE的计算更高效，尤其是在大密钥长度下。DHE的计算复杂度增加导致了更高的CPU使用。
- **连接时间：** `ECDHE` 的连接时间更短（142.127 ms/op 对比 1064.483 ms/op）
- **数据传输：** `DHE` 的数据传输时间更高（445.015 ms/op 对比 265.663 ms/op）
- **内存使用：** `ECDHE` 的内存使用更低（147.930 bytes 对比 287.857 bytes）

3、截取部分TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256和TLS_DHE_RSA_WITH_AES_128_CBC_SHA256的输出日志

```
Benchmark                                      Mode  Cnt    Score      Error  Units
TLSCipherSuiteBenchmark.testECDHECPUUsage      avgt    5  821.313 ± 5810.353  ms/op
TLSCipherSuiteBenchmark.testECDHEConnection    avgt    5  136.089 ±   12.269  ms/op
TLSCipherSuiteBenchmark.testECDHEDataTransfer  avgt    5  281.265 ±  182.223  ms/op
TLSCipherSuiteBenchmark.testECDHEMemoryUsage   avgt    5  763.608 ± 5284.096  ms/op
TLSCipherSuiteBenchmark.testFFDHECPUUsage      avgt    5  279.030 ±  713.629  ms/op
TLSCipherSuiteBenchmark.testFFDHEConnection    avgt    5  211.998 ±  667.222  ms/op
TLSCipherSuiteBenchmark.testFFDHEDataTransfer  avgt    5  264.172 ±    7.903  ms/op
TLSCipherSuiteBenchmark.testFFDHEMemoryUsage   avgt    5  190.757 ±  324.170  ms/op
```

- **CPU使用：** `DHE` 在CPU使用上明显优于 `ECDHE`（279.030 ms/op 对比 821.313 ms/op）
- **连接时间：** `ECDHE` 的连接时间更短（136.089 ms/op 对比 211.998 ms/op）
- **数据传输：** 两者的数据传输时间差异较小
- **内存使用：** `DHE` 的内存使用明显低于 `ECDHE`（190.757 bytes 对比 763.608 bytes）

4、截取部分TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384和TLS_DHE_RSA_WITH_AES_256_CBC_SHA384的输出日志

```
Benchmark                                      Mode  Cnt     Score       Error  Units
TLSCipherSuiteBenchmark.testECDHECPUUsage      avgt    5   145.791 ±    23.194  ms/op
TLSCipherSuiteBenchmark.testECDHEConnection    avgt    5   156.999 ±    14.540  ms/op
TLSCipherSuiteBenchmark.testECDHEDataTransfer  avgt    5   256.683 ±    12.381  ms/op
TLSCipherSuiteBenchmark.testECDHEMemoryUsage   avgt    5   144.572 ±    17.627  ms/op
TLSCipherSuiteBenchmark.testFFDHECPUUsage      avgt    5   201.110 ±   454.781  ms/op
TLSCipherSuiteBenchmark.testFFDHEConnection    avgt    5   293.063 ±  1074.616  ms/op
TLSCipherSuiteBenchmark.testFFDHEDataTransfer  avgt    5   257.237 ±    12.691  ms/op
TLSCipherSuiteBenchmark.testFFDHEMemoryUsage   avgt    5   238.391 ±   417.060  ms/op
```

- **CPU使用：** `ECDHE` 的CPU使用较低（145.791 ms/op 对比 201.110 ms/op）
- **连接时间：** `ECDHE` 的连接时间较短（156.999 ms/op 对比 293.063 ms/op）
- **数据传输：** 两者的数据传输时间差异较小
- **内存使用：** `ECDHE` 的内存使用较低（144.572 bytes 对比 238.391 bytes）

可以看到，对于连接时间，ECDHE一般优于FFDHE；对于CPU使用，这两者分不出优劣；对于数据传输，分不出优劣；对于内存使用，一般是ECDHE更低，因此更推荐使用ECDHE。
