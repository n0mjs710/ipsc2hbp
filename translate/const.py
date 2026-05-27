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
# cadence; the OTA behavior of the repeater itself uses a ~360 ms (6-burst)
# wall-clock timer before resyncing — we mirror that threshold here, though
# whether the IP receive path requires the same value is not confirmed.
MAX_SYNTH_BURSTS = 6        # consecutive synthesized bursts → ~360 ms
