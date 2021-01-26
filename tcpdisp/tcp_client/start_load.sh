#!/bin/sh

for(( i=0;i<1000;i++ ))
do
./tcp_client > $i.txt &
done
