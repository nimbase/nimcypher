# Edwards curve arithmetic and Montgomery scalar multiplication.
#
# Ported from `monocypher.c` (Monocypher 4.0.3).
#
# This file is dual-licensed under BSD-2-Clause OR CC0-1.0.

import ../common
import ./fe
import ./edl

{.push checks: off.}

type
  Ge* = object
    x*, y*, z*, t*: Fe
  GeCached* = object
    yp*, ym*, z*, t2*: Fe
  GePrecomp* = object
    yp*, ym*, t2*: Fe

proc geZero*(p: var Ge) {.inline.} =
  feZero(p.x)
  feOneSet(p.y)
  feOneSet(p.z)
  feZero(p.t)

proc geTobytes*(s: BytePtr, h: var Ge) =
  var recip, x, y: Fe
  feInvert(recip, h.z)
  feMul(x, h.x, recip)
  feMul(y, h.y, recip)
  feTobytes(s, y)
  s[31] = s[31] xor byte(feIsOdd(x) shl 7)
  wipe(recip)
  wipe(x)
  wipe(y)

# h = -s, where s is a point encoded in 32 bytes.
# Variable time! Inputs must not be secret!
proc geFrombytesNegVartime*(h: var Ge, s: BytePtr): int =
  feFrombytes(h.y, s)
  feOneSet(h.z)
  feSq(h.t, h.y)         # t =   y^2
  feMul(h.x, h.t, d)     # x = d*y^2
  feSub(h.t, h.t, h.z)   # t =   y^2 - 1
  feAdd(h.x, h.x, h.z)   # x = d*y^2 + 1
  feMul(h.x, h.t, h.x)   # x = (y^2 - 1) * (d*y^2 + 1)
  let isSquare = invsqrt(h.x, h.x)
  if isSquare == 0:
    return -1 # not on the curve, abort
  feMul(h.x, h.t, h.x)   # x = sqrt((y^2 - 1) / (d*y^2 + 1))
  if feIsOdd(h.x) == int(s[31] shr 7):
    feNeg(h.x, h.x)
  feMul(h.t, h.x, h.y)
  result = 0

proc geCache*(c: var GeCached, p: var Ge) {.inline.} =
  feAdd(c.yp, p.y, p.x)
  feSub(c.ym, p.y, p.x)
  feCopy(c.z, p.z)
  feMul(c.t2, p.t, D2)

# Internal buffers are not wiped! Inputs must not be secret!
proc geAdd*(s: var Ge, p: var Ge, q: var GeCached) =
  var a, b: Fe
  feAdd(a, p.y, p.x)
  feSub(b, p.y, p.x)
  feMul(a, a, q.yp)
  feMul(b, b, q.ym)
  feAdd(s.y, a, b)
  feSub(s.x, a, b)
  feAdd(s.z, p.z, p.z)
  feMul(s.z, s.z, q.z)
  feMul(s.t, p.t, q.t2)
  feAdd(a, s.z, s.t)
  feSub(b, s.z, s.t)
  feMul(s.t, s.x, s.y)
  feMul(s.x, s.x, b)
  feMul(s.y, s.y, a)
  feMul(s.z, a, b)

proc geSub*(s: var Ge, p: var Ge, q: var GeCached) =
  var neg: GeCached
  feCopy(neg.ym, q.yp)
  feCopy(neg.yp, q.ym)
  feCopy(neg.z, q.z)
  feNeg(neg.t2, q.t2)
  geAdd(s, p, neg)

proc geMadd*(s: var Ge, p: var Ge, q: GePrecomp, a, b: var Fe) =
  feAdd(a, p.y, p.x)
  feSub(b, p.y, p.x)
  feMul(a, a, q.yp)
  feMul(b, b, q.ym)
  feAdd(s.y, a, b)
  feSub(s.x, a, b)
  feAdd(s.z, p.z, p.z)
  feMul(s.t, p.t, q.t2)
  feAdd(a, s.z, s.t)
  feSub(b, s.z, s.t)
  feMul(s.t, s.x, s.y)
  feMul(s.x, s.x, b)
  feMul(s.y, s.y, a)
  feMul(s.z, a, b)

proc geMsub*(s: var Ge, p: var Ge, q: GePrecomp, a, b: var Fe) =
  var neg: GePrecomp
  feCopy(neg.ym, q.yp)
  feCopy(neg.yp, q.ym)
  feNeg(neg.t2, q.t2)
  geMadd(s, p, neg, a, b)

proc geDouble*(s: var Ge, p: var Ge, q: var Ge) =
  feSq(q.x, p.x)
  feSq(q.y, p.y)
  feSq(q.z, p.z)          # qZ = pZ^2
  feMulSmall(q.z, q.z, 2) # qZ = pZ^2 * 2
  feAdd(q.t, p.x, p.y)
  feSq(s.t, q.t)
  feAdd(q.t, q.y, q.x)
  feSub(q.y, q.y, q.x)
  feSub(q.x, s.t, q.t)
  feSub(q.z, q.z, q.y)
  feMul(s.x, q.x, q.z)
  feMul(s.y, q.t, q.y)
  feMul(s.z, q.y, q.z)
  feMul(s.t, q.x, q.t)

# 5-bit signed window in cached format (Niels coordinates, Z=1)
const
  bWindow*: array[8, GePrecomp] = [
    GePrecomp(yp: [int32 25967493, -14356035, 29566456, 3660896, -12694345,
             4014787, 27544626, -11754271, -6079156, 2047605],
             ym: [int32 -12545711, 934262, -2722910, 3049990, -727428,
             9406986, 12720692, 5043384, 19500929, -15469378],
             t2: [int32 -8738181, 4489570, 9688441, -14785194, 10184609,
             -12363380, 29287919, 11864899, -24514362, -4438546]),
    GePrecomp(yp: [int32 15636291, -9688557, 24204773, -7912398, 616977,
             -16685262, 27787600, -14772189, 28944400, -1550024],
             ym: [int32 16568933, 4717097, -11556148, -1102322, 15682896,
             -11807043, 16354577, -11775962, 7689662, 11199574],
             t2: [int32 30464156, -5976125, -11779434, -15670865, 23220365,
             15915852, 7512774, 10017326, -17749093, -9920357]),
    GePrecomp(yp: [int32 10861363, 11473154, 27284546, 1981175, -30064349,
             12577861, 32867885, 14515107, -15438304, 10819380],
             ym: [int32 4708026, 6336745, 20377586, 9066809, -11272109,
             6594696, -25653668, 12483688, -12668491, 5581306],
             t2: [int32 19563160, 16186464, -29386857, 4097519, 10237984,
             -4348115, 28542350, 13850243, -23678021, -15815942]),
    GePrecomp(yp: [int32 5153746, 9909285, 1723747, -2777874, 30523605,
             5516873, 19480852, 5230134, -23952439, -15175766],
             ym: [int32 -30269007, -3463509, 7665486, 10083793, 28475525,
             1649722, 20654025, 16520125, 30598449, 7715701],
             t2: [int32 28881845, 14381568, 9657904, 3680757, -20181635,
             7843316, -31400660, 1370708, 29794553, -1409300]),
    GePrecomp(yp: [int32 -22518993, -6692182, 14201702, -8745502, -23510406,
             8844726, 18474211, -1361450, -13062696, 13821877],
             ym: [int32 -6455177, -7839871, 3374702, -4740862, -27098617,
             -10571707, 31655028, -7212327, 18853322, -14220951],
             t2: [int32 4566830, -12963868, -28974889, -12240689, -7602672,
             -2830569, -8514358, -10431137, 2207753, -3209784]),
    GePrecomp(yp: [int32 -25154831, -4185821, 29681144, 7868801, -6854661,
             -9423865, -12437364, -663000, -31111463, -16132436],
             ym: [int32 25576264, -2703214, 7349804, -11814844, 16472782,
             9300885, 3844789, 15725684, 171356, 6466918],
             t2: [int32 23103977, 13316479, 9739013, -16149481, 817875,
             -15038942, 8965339, -14088058, -30714912, 16193877]),
    GePrecomp(yp: [int32 -33521811, 3180713, -2394130, 14003687, -16903474,
             -16270840, 17238398, 4729455, -18074513, 9256800],
             ym: [int32 -25182317, -4174131, 32336398, 5036987, -21236817,
             11360617, 22616405, 9761698, -19827198, 630305],
             t2: [int32 -13720693, 2639453, -24237460, -7406481, 9494427,
             -5774029, -6554551, -15960994, -2449256, -14291300]),
    GePrecomp(yp: [int32 -3151181, -5046075, 9282714, 6866145, -31907062,
             -863023, -18940575, 15033784, 25105118, -7894876],
             ym: [int32 -24326370, 15950226, -31801215, -14592823, -11662737,
             -5090925, 1573892, -2625887, 2198790, -15804619],
             t2: [int32 -3099351, 10324967, -2241613, 7453183, -5446979,
             -2735503, -13812022, -16236442, -32461234, -12290683]),
  ]

  bCombLow: array[8, GePrecomp] = [
    GePrecomp(yp: [int32 -6816601, -2324159, -22559413, 124364, 18015490,
             8373481, 19993724, 1979872, -18549925, 9085059],
             ym: [int32 10306321, 403248, 14839893, 9633706, 8463310,
             -8354981, -14305673, 14668847, 26301366, 2818560],
             t2: [int32 -22701500, -3210264, -13831292, -2927732, -16326337,
             -14016360, 12940910, 177905, 12165515, -2397893]),
    GePrecomp(yp: [int32 -12282262, -7022066, 9920413, -3064358, -32147467,
             2927790, 22392436, -14852487, 2719975, 16402117],
             ym: [int32 -7236961, -4729776, 2685954, -6525055, -24242706,
             -15940211, -6238521, 14082855, 10047669, 12228189],
             t2: [int32 -30495588, -12893761, -11161261, 3539405, -11502464,
             16491580, -27286798, -15030530, -7272871, -15934455]),
    GePrecomp(yp: [int32 17650926, 582297, -860412, -187745, -12072900,
             -10683391, -20352381, 15557840, -31072141, -5019061],
             ym: [int32 -6283632, -2259834, -4674247, -4598977, -4089240,
             12435688, -31278303, 1060251, 6256175, 10480726],
             t2: [int32 -13871026, 2026300, -21928428, -2741605, -2406664,
             -8034988, 7355518, 15733500, -23379862, 7489131]),
    GePrecomp(yp: [int32 6883359, 695140, 23196907, 9644202, -33430614,
             11354760, -20134606, 6388313, -8263585, -8491918],
             ym: [int32 -7716174, -13605463, -13646110, 14757414, -19430591,
             -14967316, 10359532, -11059670, -21935259, 12082603],
             t2: [int32 -11253345, -15943946, 10046784, 5414629, 24840771,
             8086951, -6694742, 9868723, 15842692, -16224787]),
    GePrecomp(yp: [int32 9639399, 11810955, -24007778, -9320054, 3912937,
             -9856959, 996125, -8727907, -8919186, -14097242],
             ym: [int32 7248867, 14468564, 25228636, -8795035, 14346339,
             8224790, 6388427, -7181107, 6468218, -8720783],
             t2: [int32 15513115, 15439095, 7342322, -10157390, 18005294,
             -7265713, 2186239, 4884640, 10826567, 7135781]),
    GePrecomp(yp: [int32 -14204238, 5297536, -5862318, -6004934, 28095835,
             4236101, -14203318, 1958636, -16816875, 3837147],
             ym: [int32 -5511166, -13176782, -29588215, 12339465, 15325758,
             -15945770, -8813185, 11075932, -19608050, -3776283],
             t2: [int32 11728032, 9603156, -4637821, -5304487, -7827751,
             2724948, 31236191, -16760175, -7268616, 14799772]),
    GePrecomp(yp: [int32 -28842672, 4840636, -12047946, -9101456, -1445464,
             381905, -30977094, -16523389, 1290540, 12798615],
             ym: [int32 27246947, -10320914, 14792098, -14518944, 5302070,
             -8746152, -3403974, -4149637, -27061213, 10749585],
             t2: [int32 25572375, -6270368, -15353037, 16037944, 1146292,
             32198, 23487090, 9585613, 24714571, -1418265]),
    GePrecomp(yp: [int32 19844825, 282124, -17583147, 11004019, -32004269,
             -2716035, 6105106, -1711007, -21010044, 14338445],
             ym: [int32 8027505, 8191102, -18504907, -12335737, 25173494,
             -5923905, 15446145, 7483684, -30440441, 10009108],
             t2: [int32 -14134701, -4174411, 10246585, -14677495, 33553567,
             -14012935, 23366126, 15080531, -7969992, 7663473]),
  ]

  bCombHigh: array[8, GePrecomp] = [
    GePrecomp(yp: [int32 33055887, -4431773, -521787, 6654165, 951411,
             -6266464, -5158124, 6995613, -5397442, -6985227],
             ym: [int32 4014062, 6967095, -11977872, 3960002, 8001989,
             5130302, -2154812, -1899602, -31954493, -16173976],
             t2: [int32 16271757, -9212948, 23792794, 731486, -25808309,
             -3546396, 6964344, -4767590, 10976593, 10050757]),
    GePrecomp(yp: [int32 2533007, -4288439, -24467768, -12387405, -13450051,
             14542280, 12876301, 13893535, 15067764, 8594792],
             ym: [int32 20073501, -11623621, 3165391, -13119866, 13188608,
             -11540496, -10751437, -13482671, 29588810, 2197295],
             t2: [int32 -1084082, 11831693, 6031797, 14062724, 14748428,
             -8159962, -20721760, 11742548, 31368706, 13161200]),
    GePrecomp(yp: [int32 2050412, -6457589, 15321215, 5273360, 25484180,
             124590, -18187548, -7097255, -6691621, -14604792],
             ym: [int32 9938196, 2162889, -6158074, -1711248, 4278932,
             -2598531, -22865792, -7168500, -24323168, 11746309],
             t2: [int32 -22691768, -14268164, 5965485, 9383325, 20443693,
             5854192, 28250679, -1381811, -10837134, 13717818]),
    GePrecomp(yp: [int32 -8495530, 16382250, 9548884, -4971523, -4491811,
             -3902147, 6182256, -12832479, 26628081, 10395408],
             ym: [int32 27329048, -15853735, 7715764, 8717446, -9215518,
             -14633480, 28982250, -5668414, 4227628, 242148],
             t2: [int32 -13279943, -7986904, -7100016, 8764468, -27276630,
             3096719, 29678419, -9141299, 3906709, 11265498]),
    GePrecomp(yp: [int32 11918285, 15686328, -17757323, -11217300, -27548967,
             4853165, -27168827, 6807359, 6871949, -1075745],
             ym: [int32 -29002610, 13984323, -27111812, -2713442, 28107359,
             -13266203, 6155126, 15104658, 3538727, -7513788],
             t2: [int32 14103158, 11233913, -33165269, 9279850, 31014152,
             4335090, -1827936, 4590951, 13960841, 12787712]),
    GePrecomp(yp: [int32 1469134, -16738009, 33411928, 13942824, 8092558,
             -8778224, -11165065, 1437842, 22521552, -2792954],
             ym: [int32 31352705, -4807352, -25327300, 3962447, 12541566,
             -9399651, -27425693, 7964818, -23829869, 5541287],
             t2: [int32 -25732021, -6864887, 23848984, 3039395, -9147354,
             6022816, -27421653, 10590137, 25309915, -1584678]),
    GePrecomp(yp: [int32 -22951376, 5048948, 31139401, -190316, -19542447,
             -626310, -17486305, -16511925, -18851313, -12985140],
             ym: [int32 -9684890, 14681754, 30487568, 7717771, -10829709,
             9630497, 30290549, -10531496, -27798994, -13812825],
             t2: [int32 5827835, 16097107, -24501327, 12094619, 7413972,
             11447087, 28057551, -1793987, -14056981, 4359312]),
    GePrecomp(yp: [int32 26323183, 2342588, -21887793, -1623758, -6062284,
             2107090, -28724907, 9036464, -19618351, -13055189],
             ym: [int32 -29697200, 14829398, -4596333, 14220089, -30022969,
             2955645, 12094100, -13693652, -5941445, 7047569],
             t2: [int32 -3201977, 14413268, -12058324, -16417589, -9035655,
             -7224648, 9258160, 1399236, 30397584, -5684634]),
  ]

type
  SlideCtx* = object
    nextIndex*: int16 # position of the next signed digit
    nextDigit*: int8  # next signed digit (odd number below 2^window_width)
    nextCheck*: uint8 # point at which we must check for a new window

proc slideInit*(ctx: var SlideCtx, scalar: BytePtr) {.inline.} =
  var i = 252
  while i > 0 and scalarBit(scalar, i) == 0:
    i -= 1
  ctx.nextCheck = uint8(i + 1)
  ctx.nextIndex = -1
  ctx.nextDigit = -1

proc slideStep*(ctx: var SlideCtx, width, i: int, scalar: BytePtr): int {.inline.} =
  if i == int(ctx.nextCheck):
    if scalarBit(scalar, i) == scalarBit(scalar, i - 1):
      ctx.nextCheck -= 1
    else:
      # compute digit of next window
      let w = min(width, i + 1)
      var v = -(scalarBit(scalar, i) shl (w - 1))
      for j in 0 ..< (w - 1):
        v += scalarBit(scalar, i - (w - 1) + j) shl j
      v += scalarBit(scalar, i - w)
      let lsb = v and (not v + 1) # smallest bit of v
      # s = log2(lsb)
      let s = int((lsb and 0xAA) != 0) or
              (int((lsb and 0xCC) != 0) shl 1) or
              (int((lsb and 0xF0) != 0) shl 2)
      ctx.nextIndex = int16(i - (w - 1) + s)
      ctx.nextDigit = int8(v shr s)
      ctx.nextCheck -= uint8(w)
  result = if i == int(ctx.nextIndex): int(ctx.nextDigit) else: 0

const
  P_W_WIDTH* = 3 # affects the size of the stack
  B_W_WIDTH* = 5 # affects the size of the binary
  P_W_SIZE* = 1 shl (P_W_WIDTH - 2)

proc lookupAdd(p: var Ge, tmpC: var GePrecomp, tmpA, tmpB: var Fe,
               comb: array[8, GePrecomp], scalar: BytePtr, i: int) =
  let teeth = uint8(scalarBit(scalar, i) +
                    (scalarBit(scalar, i + 32) shl 1) +
                    (scalarBit(scalar, i + 64) shl 2) +
                    (scalarBit(scalar, i + 96) shl 3))
  let high = int(teeth shr 3)
  let index = int((teeth xor uint8(high - 1)) and 7)
  for j in 0 ..< 8:
    let select = int(1 and (((j xor index) - 1) shr 8))
    feCcopy(tmpC.yp, comb[j].yp, select)
    feCcopy(tmpC.ym, comb[j].ym, select)
    feCcopy(tmpC.t2, comb[j].t2, select)
  feNeg(tmpA, tmpC.t2)
  feCswap(tmpC.t2, tmpA, high xor 1)
  feCswap(tmpC.yp, tmpC.ym, high xor 1)
  geMadd(p, p, tmpC, tmpA, tmpB)

# p = [scalar]B, where B is the base point
proc geScalarmultBase*(p: var Ge, scalar: BytePtr) =
  # twin 4-bits signed combs, from Mike Hamburg's
  # "Fast and compact elliptic-curve cryptography" (2012)
  const
    halfModL: array[32, byte] = [
      247, 233, 122, 46, 141, 49, 9, 44, 107, 206, 123, 81, 239, 124, 111, 10,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
    ]
    halfOnes: array[32, byte] = [
      142, 74, 204, 70, 186, 24, 118, 107, 184, 231, 190, 57, 250, 173, 119, 99,
      255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 7,
    ]
  # all bits set form: 1 means 1, 0 means -1
  var sScalar: array[32, byte]
  mulAdd(cast[BytePtr](unsafeAddr sScalar[0]), scalar,
         cast[BytePtr](unsafeAddr halfModL[0]),
         cast[BytePtr](unsafeAddr halfOnes[0]))
  # double and add ladder
  var tmpA, tmpB: Fe # temporaries for addition
  var tmpC: GePrecomp # temporary for comb lookup
  var tmpD: Ge # temporary for doubling
  feOneSet(tmpC.yp)
  feOneSet(tmpC.ym)
  feZero(tmpC.t2)
  # save a double on the first iteration
  geZero(p)
  lookupAdd(p, tmpC, tmpA, tmpB, bCombLow,
            cast[BytePtr](unsafeAddr sScalar[0]), 31)
  lookupAdd(p, tmpC, tmpA, tmpB, bCombHigh,
            cast[BytePtr](unsafeAddr sScalar[0]), 31 + 128)
  # regular double & add for the rest
  for i in countdown(30, 0):
    geDouble(p, p, tmpD)
    lookupAdd(p, tmpC, tmpA, tmpB, bCombLow,
              cast[BytePtr](unsafeAddr sScalar[0]), i)
    lookupAdd(p, tmpC, tmpA, tmpB, bCombHigh,
              cast[BytePtr](unsafeAddr sScalar[0]), i + 128)
  wipe(tmpA)
  wipe(tmpD)
  wipe(tmpB)
  wipe(tmpC)
  wipe(sScalar)

# Montgomery ladder scalar multiplication
proc scalarmult*(q: BytePtr, scalar: BytePtr, p: BytePtr, nbBits: int) =
  var x1: Fe
  feFrombytes(x1, p)
  var x2, z2, x3, z3, t0, t1: Fe
  feOneSet(x2)
  feZero(z2) # "zero" point
  feCopy(x3, x1)
  feOneSet(z3) # "one" point
  var swap = 0
  var pos = nbBits - 1
  while pos >= 0:
    # constant time conditional swap before ladder step
    let b = scalarBit(scalar, pos)
    swap = swap xor b # xor trick avoids swapping at the end of the loop
    feCswap(x2, x3, swap)
    feCswap(z2, z3, swap)
    swap = b # anticipates one last swap after the loop
    # Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
    feSub(t0, x3, z3)
    feSub(t1, x2, z2)
    feAdd(x2, x2, z2)
    feAdd(z2, x3, z3)
    feMul(z3, t0, x2)
    feMul(z2, z2, t1)
    feSq(t0, t1)
    feSq(t1, x2)
    feAdd(x3, z3, z2)
    feSub(z2, z3, z2)
    feMul(x2, t1, t0)
    feSub(t1, t1, t0)
    feSq(z2, z2)
    feMulSmall(z3, t1, 121666)
    feSq(x3, x3)
    feAdd(t0, t0, z3)
    feMul(z3, x1, z2)
    feMul(z2, t1, t0)
    pos -= 1
  # last swap is necessary to compensate for the xor trick
  feCswap(x2, x3, swap)
  feCswap(z2, z3, swap)
  # normalise the coordinates: x == X / Z
  feInvert(z2, z2)
  feMul(x2, x2, z2)
  feTobytes(q, x2)
  wipe(x1)
  wipe(x2)
  wipe(z2)
  wipe(t0)
  wipe(x3)
  wipe(z3)
  wipe(t1)

# Select low order point
proc selectLop*(outp: var Fe, x, k: Fe, cofactor: byte) =
  var tmp: Fe
  feZero(outp)
  feCcopy(outp, k, int((cofactor shr 1) and 1)) # bit 1
  feCcopy(outp, x, int((cofactor shr 0) and 1)) # bit 0
  feNeg(tmp, outp)
  feCcopy(outp, tmp, int((cofactor shr 2) and 1)) # bit 2
  wipe(tmp)

{.pop.}
