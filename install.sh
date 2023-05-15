#!/bin/bash
# Path: install.sh
# 在Codespace中运行将自动安装LevelDB依赖
cd /tmp
export VER="1.20"
wget https://github.com/google/leveldb/archive/v${VER}.tar.gz
tar xvf v${VER}.tar.gz
rm -f v${VER}.tar.gz
cd leveldb-${VER}
make
sudo scp -r out-static/lib* out-shared/lib* "/usr/local/lib"
cd include
sudo cp -r leveldb /usr/local/include
sudo chmod 645 /usr/local/include/leveldb
sudo ldconfig