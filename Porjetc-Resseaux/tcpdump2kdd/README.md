# Commands to run

```
sudo tcpdump -w zozo.pcap -i en0
```

```
bro -r zozo.pcap darpa2gurekddcup.bro > zozo.list
```

It needs to sort the file according to the field *num_conn*. This helps the algorithm in the next step (python)
```
sort -n zozo.list > zizi.list
```

```
python3 convert.py --in_file zizi.list --out_file FAKE_KDD.txt
```