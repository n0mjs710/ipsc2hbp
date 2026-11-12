# ---------------------------------------------------------------------------
# Translator timing constants — tune here, not in config.toml
# ---------------------------------------------------------------------------

# Number of 60 ms TDMA slots buffered before the first delivery to IPSC.
# Incoming HBP bursts are held in a position-indexed dict; the delivery timer
# fires every 60 ms and sends whatever is in the buffer (real AMBE) or
# synthesises AMBE silence if the slot is empty.  The buffer depth sets the
# maximum HBP delivery jitter that can be absorbed without synthesising:
#
#   depth=2 → 120 ms lookahead; absorbs jitter up to 120 ms (observed: 50–72 ms)
#
# This also adds 120 ms of end-to-end latency, which is imperceptible on
# half-duplex PTT radio (c-Bridge already adds 500 ms–2 s in typical configs).
JITTER_BUFFER_DEPTH = 2     # slots (× 60 ms = 120 ms initial delay)

# Maximum consecutive synthesized silence bursts before giving up on the
# stream.  At 60 ms per burst this is the wall-clock holdoff before we
# consider the call dead and call _on_stream_timeout().
#
# Empirical testing suggests MOTOTRBO repeaters struggle with the loss of
# more than one burst frame and appear to expect filler frames at the 60 ms
# cadence, which the clock keeps sending while it fills.  The repeater's own
# OTA resync timer is ~360 ms (6 bursts), where the old value of 6 came from;
# how long to fill is a network question, not an RF one: a network call
# pauses longer than 360 ms (internet jitter, a partner network stalling a
# few hundred ms), and ending it at 360 ms cut live calls in two (the next
# burst came back as a late entry, a new call to the repeater).  1.5 s is
# MMDVMHost's network watchdog (DMRSlot m_networkWatchdog); it fills
# silence until then.
MAX_SYNTH_BURSTS = 25       # consecutive synthesized bursts → 1.5 s
