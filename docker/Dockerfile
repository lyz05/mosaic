FROM ghcr.io/z3prover/z3:ubuntu-20.04-bare-z3-sha-0c9a5f6
MAINTAINER lyz05 <liuyuanzhe0515@gmail.com>

RUN mkdir /source

RUN  apt-get update \
  && apt-get install -y wget redis \
  && rm -rf /var/lib/apt/lists/*

# building levelDB from sources
RUN cd /tmp && \
    wget https://github.com/google/leveldb/archive/v1.20.tar.gz && \
    tar xvf v1.20.tar.gz && \
    rm -rf v1.20.tar.gz && \
    cd leveldb-1.20 && \
    make && \
    cp -r out-static/lib* out-shared/lib* /usr/local/lib/ && \
    cd include && \
    cp -r leveldb /usr/local/include/ && \
    ldconfig


# building z3 from sources
# RUN cd /source && \
#     wget https://github.com/Z3Prover/z3/archive/z3-4.8.7.tar.gz && \
#     tar xvf z3-4.8.7.tar.gz && \
#     cd z3-z3-4.8.7 && \
#     python3 scripts/mk_make.py && \
#     cd build && \
#     make -j 8 && make install && \
#     rm -rf /source/z3-z3-4.8.7

# building gmp from sources
#RUN cd /source && \
#    wget https://gmplib.org/download/gmp/gmp-6.2.0.tar.lz && \
#    lzip -d gmp-6.2.0.tar.lz && \
#    tar xvf gmp-6.2.0.tar && \
#    cd gmp-6.2.0 && \
#    ./configure && make -j 8 && make install && ldconfig && \
#    rm -rf /source/gmp-6.2.0

# building pbc from sources
#RUN cd /source && \
#    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
#    tar xvf pbc-0.5.14.tar.gz && \
#    cd pbc-0.5.14 && \
#    ./configure && make -j 8 && make install && \
#    echo "/usr/local/lib" > /etc/ld.so.conf.d/pbc.conf && ldconfig -v && \
#    rm -rf /source/pbc-0.5.14

RUN wget https://dl.google.com/go/go1.20.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.3.linux-amd64.tar.gz

# RUN yum install -y \
#     redis

# RUN yum install -y \
#     leveldb leveldb-devel

#RUN cd /source && \
#    git clone https://github.com/miracl/MIRACL

ENV PATH="${PATH}:/usr/local/go/bin"

RUN mkdir /mosaic
ADD ./abe /mosaic/abe
ADD ./lib/mosaic.go /mosaic/lib
ADD ./examples /mosaic/examples
ADD ./service /mosaic/service
ADD go.mod /mosaic
ADD go.sum /mosaic

ADD ./docker/docker-entrypoint.sh /mosaic

WORKDIR /mosaic

ENTRYPOINT ["/mosaic/docker-entrypoint.sh"]

CMD ["/bin/bash"]
