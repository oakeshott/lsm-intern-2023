# lsm-intern-2023

## Create Learned Model
```bash
cd src/kernel-packet-processing/fixed-nn/src
python train_mlp.py --save_dir ../saved_models/nn/binary-classification/16x16 --hidden_sizes 16 16 --num_epochs 30 --is-binary
python quantize_with_package.py --save_dir ../saved_models/cnn/binary-classification/16x16 --filename mlp_pktflw.th --num_bins 128 --calib-method histogram --is-binary # Quantization
python create_mlp_c_params.py --save_dir ${INDIR} --filename mlp_pktflw_quant.th
make
```

## Test Learned Model
```bash
BASEDIR=../saved_models/nn/binary-classification/
model=16x16
INDIR=${BASEDIR}/16x16
echo "TEST for Pytorch"
ARR=(${model//x/ })
python test_mlp.py --save_dir $INDIR --hidden_sizes ${ARR[0]} ${ARR[1]} --is-binary
echo "TEST for C implement"
python test_mlp_c.py --save_dir $INDIR --is-binary
```

## XDP

```bash
cd src/kernel-packet-processing/nn-filter
sudo PYTHONIOENCODING=utf-8 PYTHONPATH=${PYTHONPATH} python3.9 nn_filter_xdp.py <ifdev> <output-file> -S
```
