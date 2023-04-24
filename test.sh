#!/bin/bash

do_tests () {
  KEY="ABCDEF12ABCDEF12"

  mkdir -p ${NAME}-results

  echo "ABC" | ${BIN} enc -des-ecb -K ${KEY} > ${NAME}-results/test0.enc
  ${BIN} enc -des-ecb -d -K ${KEY} < ${NAME}-results/test0.enc > ${NAME}-results/test0.plain

  echo "ABCD" | ${BIN} enc -des-ecb -K ${KEY} > ${NAME}-results/test1.enc
  ${BIN} enc -des-ecb -d -K ${KEY} < ${NAME}-results/test1.enc > ${NAME}-results/test1.plain

  echo "The dog runs fast." | ${BIN} enc -des-ecb -K ${KEY} > ${NAME}-results/test2.enc
  ${BIN} enc -des-ecb -d -K ${KEY} < ${NAME}-results/test2.enc > ${NAME}-results/test2.plain
}

BIN="./myssl"
NAME="myssl"

do_tests

BIN="openssl"
NAME="openssl"

do_tests

diff -r --brief myssl-results openssl-results
