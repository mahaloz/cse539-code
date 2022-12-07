PIN_BIN=./intel-pin/pin-3.25-98650-g8f6168173-gcc-linux/pin
TRACE_BIN=./intel-pin/pin-3.25-98650-g8f6168173-gcc-linux/source/tools/ManualExamples/obj-intel64/inscount0.so

#
# Express counting
# 

(cd Express/serverB && ./serverB 1 1 10 10)
(cd Express/serverA && ./serverA localhost:4442 1 1 10 10) 
./intel-pin/pin-3.25-98650-g8f6168173-gcc-linux/pin -t "$TRACE_BIN" -- ./Express/client/client localhost:4443 localhost:4442 1 10
echo "====== Express SCORE ======"
cat inscount.out
rm -f inscount.out

#
# Riposte
# 

# kill after 500 insn
(cd ./Riposte/server && ./riposte)
timeout 5 ./intel-pin/pin-3.25-98650-g8f6168173-gcc-linux/pin -t "$TRACE_BIN" -- ./Riposte/client/client -leader localhost:9090 -hammer
echo "====== Riposte SCORE ======"
cat inscount.out
rm -f inscount.out

#
# Sabre
#

timeout 5 ./intel-pin/pin-3.25-98650-g8f6168173-gcc-linux/pin -t "$TRACE_BIN" -- ./Sabre/Sabre-write/bin/sabre
echo "====== Sabre SCORE ======"
cat inscount.out
rm -f inscount.out
