# pcap2erf

![Alt text](http://fmad.io/analytics/logo_capmerge.png "fmadio PCAP to ERF converter")

High performance PCAP to ERF conversion utility 

Usage:

```
cat sample.pcap | ./pcap2erf > sample.erf
```


#performance


Mostly limited by IO thoughput. example below is reading from SSD and writing to /dev/null

Getting sustained ~ 5.5Gbps throughput, dataset is 64B line rate packets (10Gbps) with larger packets the thoughput will be higher


```
fmadio@fmadio20n40v3-363:/mnt/store0/git/pcap2erf$ sudo stream_cat -v asdf_20210711_0638 | ./pcap2erf  > /dev/null
0M Offset:    0GB Pkt:1625953135_111814713 Length:  64 Capture:  64 ChunkID:3648876 0.202Gbps CPUIdle:0.000
8M Offset:    0GB Pkt:1625953135_269522330 Length:  64 Capture:  64 ChunkID:3651550 5.607Gbps CPUIdle:0.000
17M Offset:    1GB Pkt:1625953135_427408714 Length:  64 Capture:  64 ChunkID:3654227 5.614Gbps CPUIdle:0.000
26M Offset:    1GB Pkt:1625953135_584729251 Length:  64 Capture:  64 ChunkID:3656895 5.594Gbps CPUIdle:0.000
35M Offset:    2GB Pkt:1625953135_742179406 Length:  64 Capture:  64 ChunkID:3659565 5.598Gbps CPUIdle:0.000
43M Offset:    3GB Pkt:1625953135_899668322 Length:  64 Capture:  64 ChunkID:3662236 5.600Gbps CPUIdle:0.000
52M Offset:    3GB Pkt:1625953136_057017722 Length:  64 Capture:  64 ChunkID:3664905 5.595Gbps CPUIdle:0.000
61M Offset:    4GB Pkt:1625953136_214392165 Length:  64 Capture:  64 ChunkID:3667573 5.596Gbps CPUIdle:0.000
69M Offset:    5GB Pkt:1625953136_371812711 Length:  64 Capture:  64 ChunkID:3670243 5.597Gbps CPUIdle:0.000
78M Offset:    5GB Pkt:1625953136_529246816 Length:  64 Capture:  64 ChunkID:3672913 5.598Gbps CPUIdle:0
```
