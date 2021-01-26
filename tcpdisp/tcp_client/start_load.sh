#!/bin/sh

for(( i=0;i<10;i++ ))
do
./tcp_client > $i.txt &
done
