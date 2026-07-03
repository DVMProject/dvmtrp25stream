# DVM-TR-P25-Stream

Streams near-real-time P25 FDMA call data from trunk-recorder directly into a DVMProject FNE-style by connecting to the FNE as a standard FNE peer. The plugin converts IMBE vectors received over the air, into DVMProject FNE network payloads allowing direct connection of a scanned P25 FDMA source to a talkgroup on a DVMProject FNE.

dvmtrp25stream is designed for P25 Phase 1 FDMA voice transport *only*. It is not designed to, and will not carry P25 TDMA (Phase 2) audio.

## Building

To use dvmtrp25stream with trunk-recorder, clone this repository into the trunk-recorder `user_plugins` folder and then build trunk-recorder.

```
cd trunk-recorder/user_plugins
git clone https://github.com/DVMProject/dvmtrp25stream.git
```

For more information, see https://github.com/TrunkRecorder/trunk-recorder/blob/master/docs/Plugins.md

## Notes

- This plugin is intended for near-real-time digital forwarding workflows.
- Designed for P25 FDMA systems only.
- Not designed to carry P25 TDMA audio.
- It supports multiple active talkgroups at the same time.
- Route matching is done by TGID and optional system `shortName`.
- Routes sharing the same destination lane (`dstTgid`) are serialized one call at a time (FIFO), so many-to-one mux introduces delivery delay.
- Requires `audioStreaming: true` in trunk-recorder config to ensure real-time audio/call plumbing is active.

## Example Plugin Config

```json
{
  "name": "dvmtrp25stream",
  "library": "libdvmtrp25stream.so",
  "fne": {
    "address": "127.0.0.1",
    "port": 62031,
    "peerId": 100123,
    "password": "changeme",
    "identity": "trunk-recorder",
    "maxMissedPings": 10,
    "retryIntervalMs": 3000,
    "pacedCallTimeoutMs": 10000
  },
  "maxQueueDepth": 8192,
  "routes": [
    {
      "TGID": 3101,
      "dstTgid": 91001,
      "shortName": "MyP25System"
    },
    {
      "TGID": 3102,
      "shortName": "MyP25System"
    },
    {
      "TGID": 0,
      "shortName": "MyP25System"
    }
  ]
}
```

### FNE Fields

- Ping cadence is fixed by FNE protocol and is not configurable in dvmtrp25stream.
- `maxMissedPings`: number of consecutive keepalive `PING` messages that do not receive a `PONG` response before the session is reset and reconnect is attempted.
- `retryIntervalMs`: reconnect/login retry interval after session reset or startup.
- `pacedCallTimeoutMs`: max time to keep requeueing a paced call before dropping its blocked frames (default 10000 ms).

## Example Muxed Talkgroups

This route set muxes multiple source TGIDs into one destination TGID on the FNE. Be aware muxing will cause call queuing, and can delay or "pile up" calls.

```json
"routes": [
  {
    "TGID": 1201,
    "dstTgid": 91001,
    "shortName": "MyP25System"
  },
  {
    "TGID": 1202,
    "dstTgid": 91001,
    "shortName": "MyP25System"
  },
  {
    "TGID": 1203,
    "dstTgid": 91001,
    "shortName": "MyP25System"
  }
]
```

In this example, source TGIDs `1201`, `1202`, and `1203` are all forwarded to destination TGID `91001` and serialized in FIFO order when calls overlap.

### Route Fields

- `TGID`: talkgroup to match. `0` means wildcard (any TGID).
- `dstTgid`: optional FNE destination TGID override. When omitted or `0`, source `TGID` is used.
- Multiple source `TGID` values may target the same `dstTgid`; the plugin queues calls and replays them sequentially for that destination.
- `shortName`: optional system shortName filter.

## License

This project is licensed under the GPLv2 License - see the [LICENSE](LICENSE) file for details. Use of this project is intended, for amateur and/or educational use ONLY. Any other use is at the risk of user and all commercial purposes is strictly discouraged.

**THIS SOFTWARE MUST NEVER BE USED IN PUBLIC SAFETY OR LIFE SAFETY CRITICAL APPLICATIONS! This software project is provided solely for personal, non-commercial, hobbyist use; any commercial, professional, governmental, or other non-hobbyist use is strictly discouraged, fully unsupported and expressly disclaimed by the authors.**

By using this software, you agree to indemnify, defend, and hold harmless the authors, contributors, and affiliated  parties from and against any and all claims, liabilities, damages, losses, or expenses (including reasonable  attorneys’ fees) arising out of or relating to any unlawful, unauthorized, or improper use of the software.

