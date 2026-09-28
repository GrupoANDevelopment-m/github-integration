# NSL-KDD Dataset for Goodware Training

Source: https://github.com/Jehuty4949/NSL_KDD
License: Public

## Files
- `KDDTrain+.txt` — 125,973 training records
- `KDDTest+.txt` — 22,544 test records
- `field_names.csv` — 41 features + label + difficulty

## Features (41)
- 9 basic features (duration, protocol_type, service, flag, src_bytes, dst_bytes, ...)
- 13 content features
- 9 time-based traffic features
- 10 host-based traffic features

## Classes
- Normal traffic
- 22 attack types mapped to 4 categories:
  - **DoS** (denial of service): back, land, neptune, pod, smurf, teardrop
  - **Probe** (surveillance): satan, ipsweep, nmap, portsweep
  - **R2L** (remote to local): guess_passwd, ftp_write, imap, phf, multihop, warezmaster, warezclient
  - **U2R** (user to root): buffer_overflow, loadmodule, rootkit, perl

## Training

```bash
python3 -m goodware.prediction.training.train_nsl_kdd \
    --train data/nsl_kdd/KDDTrain+.txt \
    --test data/nsl_kdd/KDDTest+.txt \
    --output models/
```

## Results (after training)

```
RF train accuracy: 0.9999
RF test accuracy:  0.7766
```

Class breakdown (test set):
```
              precision    recall  f1-score   support
      normal       0.66      0.97      0.79      9711
      attack       0.97      0.63      0.76     12833
    accuracy                           0.78     22544
```
