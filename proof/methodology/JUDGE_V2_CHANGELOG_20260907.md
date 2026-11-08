# Market judge v2

The same recorded predictions are now evaluated by the first completed20-second bar touching a symmetric price barrier,using intrabar highs/lows. Earlier evaluation used barcloses. A retrospectivev2 recalculation does not change the signal population,directions,source times or issue times. It is not represented as the originally announcedv1 score.

## Timing and ambiguity

The market-tape loader now explicitly uses the production end-stamped20-second token convention. The earlier standalone verifier/spec described a left-edge market-tape index;this alignment is corrected here without changing any claim timestamp. The v1 files remain byte-immutable for reproduction.

Both barriers touched in the same20-second bar are counted as a miss for either direction;OHLC alone cannot establish their order. The external signal timestamp must be strictly earlier than that outcome bar's start. An unfinishedbar or missing inputtape cannot supply a winning outcome. Only completedbars ending within96hours of issue are eligible.

## Evidence continuity

Existing fullpacks and their legacy resolutionfields are retained unchanged. V3 independently computesv2 outcomes frompublicmarket data;differences fromlegacyv1 outcome fields are labelled version differences,not evidence tampering. New derivedv2 judgements are signed separately and published only after the corresponding originalsignal has already been disclosed. Unrevealedtoken,missingpack and timestamp penalties remain unchanged.

Training,selection gates,modelupdates and private policy contents are outside this change. A markettouch score is not a guarantee of fillprice or profit.
