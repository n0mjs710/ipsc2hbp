# ---------------------------------------------------------------------------
# Translator timing constants — tune here, not in config.toml
# ---------------------------------------------------------------------------

# Seconds past the expected 60ms TDMA slot boundary before we declare a burst
# missing and synthesize an AMBE-silence filler frame.  Must sit above the top
# of observed HBP delivery jitter (measured: 50–72 ms inter-packet) to avoid
# false-positive synthesis on bursts that are merely late, yet must be tight
# enough that the filler reaches the repeater before its receive buffer
# exhausts.  A real burst arriving after this window is discarded — its slot
# has already been filled.
#
# Value: 0.030 s → synthesis fires ~90 ms after the previous burst, i.e.
# 30 ms past the nominal 60 ms slot boundary.
BURST_LATE_WINDOW = 0.030   # seconds

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
