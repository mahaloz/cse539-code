
import math
import random

N_BINS = 2**24
N_SENDERS = 2**16
N_RECIPIENTS = 2**12
N_SCHECKS = int(math.sqrt(N_BINS))
N_RCHECKS = int(math.sqrt(N_BINS)*3)

""" For data accounting """
BYTES_PER_BIN = 2**12 
N_SERVERS = 2**8

print "N_BINS = %d" % N_BINS
print "N_SENDERS = %d" % N_SENDERS 
print "N_RECIPIENTS = %d" % N_RECIPIENTS
print "N_SCHECKS = %d" % N_SCHECKS
print "N_RCHECKS = %d" % N_RCHECKS
print ""

def rand_bin():
  return random.randint(0, N_BINS-1)

def rand_dest():
  return random.randint(0, N_RECIPIENTS-1)

def print_perc(tag, num, den):
  print "%s: %d/%d = %0.2f%%" % (tag, num, den, 100.0 * float(num)/den)

def main():

  bins = {}
  envelopes = {}
  received = {}
  for recip in range(N_RECIPIENTS):
    envelopes[recip] = []

  ''' Send msgs '''
  for sender in range(N_SENDERS):
    dest = rand_dest()
    envelopes[dest].append(sender)
    for check in range(N_SCHECKS):
      bins[rand_bin()] = (sender, dest)
    print "Sender %d" % sender

  print_perc("Slots filled", len(bins), N_BINS)

  total_gotten = 0
  for recip in range(N_RECIPIENTS):
    received[recip] = []
    for check in range(N_RCHECKS):
      look_in = rand_bin()
      if look_in in bins:
        (sender,dest) = bins[look_in]
        if dest == recip and sender not in received[recip]:
          received[recip].append(sender)
          total_gotten += 1
    print "Receipient %d" % recip

  print_perc("Received", total_gotten, N_SENDERS)

  total_bytes = (N_BINS * BYTES_PER_BIN)
  print "Bytes stored total: %d" % total_bytes
  print "Bytes per server (%d servers): %d" % (N_SERVERS, int(float(total_bytes)/N_SERVERS))
  print "Bytes per sender: %d" % (BYTES_PER_BIN * N_SCHECKS)
  print "Bytes per recipient: %d" % (BYTES_PER_BIN * N_RCHECKS)
  
main()
