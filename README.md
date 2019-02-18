# FMC_Rules 

## fmc_rules.py

This script does create Host-Objects, Access-Policies and Rules inside the new Policy. 
Host-Object details are specified in a text-file, specifing the Ip-Addresses.

It takes the host-file as input parameter 

```
python fmc_rules.py iphosts.txt
```

## fmc_rules_bulk.py
Same as fmc_rules.py but using BULK requests instead of single API calls. (Faster for large amounts of data!)

```
python fmc_rules_bulk.py iphosts.txt
```

## fmc_rules_delete.py
Does delete unused objects. Deleting Objects, used in Rules, is denied by the API. 
Specifiy a Filter to match Objects-Names of the Objects you want to delete.

```
python fmc_rules_delete.py "Host-Test_"
```


Tested on:
  FMC: 6.3
