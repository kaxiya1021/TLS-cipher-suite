package org.example;

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
