/**
 * 1anime.app Source Module for AnimeTV
 * Provides episodes listing, stream fetching with multi-layer decryption
 */
var oneAnime = (function(){
  'use strict';

  var BASE = "https://1anime.app";
  var PROVIDERS = ["ZenV2","Zen","Pahe","Zone","Nexus","Kiwi","Gogo","Kai"];
  var DEFAULT_PROVIDER = "ZenV2";
  var currentProvider = DEFAULT_PROVIDER;

  /* ===== Twofish Implementation ===== */
  var TF = (function(){
    var P0 = [169,103,179,232,4,253,163,118,154,36,68,95,230,120,111,49,227,233,238,43,85,139,221,60,99,28,226,198,3,223,140,93,41,229,213,188,97,31,110,219,245,46,209,112,239,162,153,217,235,114,171,199,246,138,20,122,39,73,204,133,67,203,220,237,123,210,40,205,30,234,174,156,7,211,222,84,155,23,77,26,183,100,63,191,16,172,187,12,243,116,13,54,142,173,34,193,168,158,61,134,113,0,152,250,22,136,24,47,44,247,42,115,2,70,141,50,55,117,58,19,66,228,244,202,87,72,167,196,146,83,38,177,161,25,56,176,14,186,27,197,62,94,252,219,35,64,225,215,9,75,45,82,105,177,200,76,135,131,11,71,124,231,216,164,166,218,248,137,128,180,33,132,130,198,227,143,108,190,224,236,157,10,241,96,90,69,86,212,48,175,106,160,181,65,206,5,79,107,127,254,195,185,208,89,201,6,144,74,92,29,104,57,15,223,78,240,159,249,53,88,18,194,52,21,145,174,62,129,255,81,207,102,32,121,37,8,80,150,170,1,147,214,126,17,149,242,189,192,125,148,51,101,251,59,184,98];
    var P1 = [117,243,198,244,219,123,251,200,74,211,230,107,69,125,232,75,214,50,216,253,55,113,241,225,48,15,248,27,135,250,6,63,94,186,174,91,138,0,188,157,109,193,177,14,128,93,210,213,160,132,7,20,181,144,44,163,178,115,76,84,146,116,54,81,56,176,189,90,252,96,98,150,108,66,247,16,124,40,39,140,19,149,156,199,36,70,59,112,202,227,133,203,17,208,147,184,166,131,32,255,159,119,195,204,3,111,8,191,64,231,43,226,121,12,170,130,65,58,234,185,228,154,122,143,220,141,208,239,218,197,155,95,180,229,235,10,2,221,144,28,99,224,75,100,89,46,190,102,220,34,57,71,83,49,245,249,182,72,97,165,161,45,134,173,162,22,158,7,37,240,82,101,246,237,236,171,105,41,60,23,13,110,4,155,168,104,29,187,11,18,152,114,196,127,53,160,139,228,194,106,5,153,79,175,246,164,9,68,223,212,238,151,136,167,120,85,30,233,126,35,118,47,73,169,254,222,52,25,209,142,215,207,103,192,172,67,61,38,31,206,4,237,33,26,40,145,80,92,42,137,217,24,86,87,78,201];

    function mdsRem(p, k){
      var b = (k>>>24)&0xff, c = (k>>>16)&0xff, d = (k>>>8)&0xff, e = k&0xff;
      if(p){
        b = P1[b]^((k>>>24)&0xff); c = P0[c]^((k>>>16)&0xff);
        d = P0[d]^((k>>>8)&0xff); e = P1[e]^(k&0xff);
      }
      return P0[P0[P1[P1[e]^d]^c]^b];
    }

    /* Simplified Twofish - using precomputed S-boxes approach */
    /* Full Twofish is complex; we use a minimal CTR-mode implementation */

    function u8to32(b, i){ return (b[i]|(b[i+1]<<8)|(b[i+2]<<16)|(b[i+3]<<24))>>>0; }
    function u32to8(v, b, i){ b[i]=v&0xff; b[i+1]=(v>>>8)&0xff; b[i+2]=(v>>>16)&0xff; b[i+3]=(v>>>24)&0xff; }

    function rol(x,n){ return ((x<<n)|(x>>>(32-n)))>>>0; }
    function ror(x,n){ return ((x>>>n)|(x<<(32-n)))>>>0; }

    /* RS Matrix multiply */
    function rsMultiply(a, b){
      var r = 0;
      for(var i=0;i<8;i++){
        if(b&1) r ^= a;
        var hi = a & 0x80;
        a = (a<<1)&0xff;
        if(hi) a ^= 0x4d;
        b >>>= 1;
      }
      return r;
    }

    function rsRem(x){
      var b = (x>>>24)&0xff;
      var g2 = ((b<<1)^((b&0x80)?0x14d:0))&0xff;
      var g3 = b^g2;
      x = ((x<<8)^(g3<<24)^(g2<<16)^(g3<<8)^b)>>>0;
      b = (x>>>24)&0xff;
      g2 = ((b<<1)^((b&0x80)?0x14d:0))&0xff;
      g3 = b^g2;
      x = ((x<<8)^(g3<<24)^(g2<<16)^(g3<<8)^b)>>>0;
      return x;
    }

    /* MDS multiply */
    function mdsMultiply(a, b){
      var r = 0;
      for(var i=0;i<8;i++){
        if(b&1) r ^= a;
        var hi = a & 0x80;
        a = (a<<1)&0xff;
        if(hi) a ^= 0x69;
        b >>>= 1;
      }
      return r;
    }

    function mdsColumn(x, col){
      var b = [x&0xff, (x>>>8)&0xff, (x>>>16)&0xff, (x>>>24)&0xff];
      /* MDS matrix */
      var m = [
        [0x01,0xEF,0x5B,0x5B],
        [0x5B,0xEF,0xEF,0x01],
        [0xEF,0x5B,0x01,0xEF],
        [0xEF,0x01,0xEF,0x5B]
      ];
      var r = 0;
      for(var i=0;i<4;i++){
        var v = 0;
        for(var j=0;j<4;j++){
          v ^= mdsMultiply(m[i][j], b[j]);
        }
        r |= (v&0xff)<<(i*8);
      }
      return r>>>0;
    }

    return {P0:P0, P1:P1};
  })();

  /* ===== Use WebCrypto-compatible Twofish CTR (ported from 1anime source) ===== */
  /* Since full Twofish in JS is complex, we'll use a pre-built minimal version */

  /**
   * Minimal Twofish block cipher (128-bit key, 128-bit block)
   * Ported from the @aspect-build/twofish npm package used by 1anime
   */
  var Twofish = (function(){
    // Pre-computed q-box permutations
    var q0 = [169,103,179,232,4,253,163,118,154,36,68,95,230,120,111,49,227,233,238,43,85,139,221,60,99,28,226,198,3,223,140,93,41,229,213,188,97,31,110,219,245,46,209,112,239,162,153,217,235,114,171,199,246,138,20,122,39,73,204,133,67,203,220,237,123,210,40,205,30,234,174,156,7,211,222,84,155,23,77,26,183,100,63,191,16,172,187,12,243,116,13,54,142,173,34,193,168,158,61,134,113,0,152,250,22,136,24,47,44,247,42,115,2,70,141,50,55,117,58,19,66,228,244,202,87,72,167,196,146,83,38,177,161,25,56,176,14,186,27,197,62,94,252,219,35,64,225,215,9,75,45,82,105,177,200,76,135,131,11,71,124,231,216,164,166,218,248,137,128,180,33,132,130,198,227,143,108,190,224,236,157,10,241,96,90,69,86,212,48,175,106,160,181,65,206,5,79,107,127,254,195,185,208,89,201,6,144,74,92,29,104,57,15,223,78,240,159,249,53,88,18,194,52,21,145,174,62,129,255,81,207,102,32,121,37,8,80,150,170,1,147,214,126,17,149,242,189,192,125,148,51,101,251,59,184,98];
    var q1 = [117,243,198,244,219,123,251,200,74,211,230,107,69,125,232,75,214,50,216,253,55,113,241,225,48,15,248,27,135,250,6,63,94,186,174,91,138,0,188,157,109,193,177,14,128,93,210,213,160,132,7,20,181,144,44,163,178,115,76,84,146,116,54,81,56,176,189,90,252,96,98,150,108,66,247,16,124,40,39,140,19,149,156,199,36,70,59,112,202,227,133,203,17,208,147,184,166,131,32,255,159,119,195,204,3,111,8,191,64,231,43,226,121,12,170,130,65,58,234,185,228,154,122,143,220,141,208,239,218,197,155,95,180,229,235,10,2,221,144,28,99,224,75,100,89,46,190,102,220,34,57,71,83,49,245,249,182,72,97,165,161,45,134,173,162,22,158,7,37,240,82,101,246,237,236,171,105,41,60,23,13,110,4,155,168,104,29,187,11,18,152,114,196,127,53,160,139,228,194,106,5,153,79,175,246,164,9,68,223,212,238,151,136,167,120,85,30,233,126,35,118,47,73,169,254,222,52,25,209,142,215,207,103,192,172,67,61,38,31,206,4,237,33,26,40,145,80,92,42,137,217,24,86,87,78,201];

    var MDS = [[0x01,0xEF,0x5B,0x5B],[0x5B,0xEF,0xEF,0x01],[0xEF,0x5B,0x01,0xEF],[0xEF,0x01,0xEF,0x5B]];
    var RS = [[0x01,0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E],[0xA4,0x56,0x82,0xF3,0x1E,0xC6,0x68,0xE5],[0x02,0xA1,0xFC,0xC1,0x47,0xAE,0x3D,0x19],[0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E,0x03]];

    function gfMul(a, b, p){
      var r = 0;
      for(var i=0;i<8;i++){
        if(b&1) r ^= a;
        var hi = a&0x80;
        a = (a<<1)&0xff;
        if(hi) a ^= p;
        b >>>=1;
      }
      return r;
    }

    function mdsMultiply(col){
      var r = 0;
      for(var i=0;i<4;i++){
        var v = 0;
        for(var j=0;j<4;j++){
          v ^= gfMul(MDS[i][j], (col>>>(j*8))&0xff, 0x69);
        }
        r |= (v&0xff)<<(i*8);
      }
      return r>>>0;
    }

    function rsMultiply(key8){
      // RS matrix multiply for key schedule
      var r = new Uint8Array(4);
      for(var i=0;i<4;i++){
        var v = 0;
        for(var j=0;j<8;j++){
          v ^= gfMul(RS[i][j], key8[j], 0x4d);
        }
        r[i] = v;
      }
      return r[0]|(r[1]<<8)|(r[2]<<16)|(r[3]<<24);
    }

    function h(x, L, k){
      var b = [(x)&0xff, (x>>>8)&0xff, (x>>>16)&0xff, (x>>>24)&0xff];
      if(k==4){
        b[0] = q1[b[0]]^((L[3])&0xff);
        b[1] = q0[b[1]]^((L[3]>>>8)&0xff);
        b[2] = q0[b[2]]^((L[3]>>>16)&0xff);
        b[3] = q1[b[3]]^((L[3]>>>24)&0xff);
      }
      if(k>=3){
        b[0] = q1[b[0]]^((L[2])&0xff);
        b[1] = q1[b[1]]^((L[2]>>>8)&0xff);
        b[2] = q0[b[2]]^((L[2]>>>16)&0xff);
        b[3] = q0[b[3]]^((L[2]>>>24)&0xff);
      }
      b[0] = q0[q0[b[0]]^((L[1])&0xff)]^((L[0])&0xff);
      b[1] = q0[q1[b[1]]^((L[1]>>>8)&0xff)]^((L[0]>>>8)&0xff);
      b[2] = q1[q0[b[2]]^((L[1]>>>16)&0xff)]^((L[0]>>>16)&0xff);
      b[3] = q1[q1[b[3]]^((L[1]>>>24)&0xff)]^((L[0]>>>24)&0xff);
      return mdsMultiply(b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24));
    }

    function makeKey(keyBytes){
      var k = keyBytes.length/8; // number of 64-bit units (2 for 128-bit, 4 for 256-bit)
      var Me = new Array(k);
      var Mo = new Array(k);
      var S = new Array(k);

      for(var i=0;i<k;i++){
        var off = i*8;
        Me[i] = keyBytes[off]|(keyBytes[off+1]<<8)|(keyBytes[off+2]<<16)|(keyBytes[off+3]<<24);
        Mo[i] = keyBytes[off+4]|(keyBytes[off+5]<<8)|(keyBytes[off+6]<<16)|(keyBytes[off+7]<<24);
        S[k-1-i] = rsMultiply(keyBytes.slice(off, off+8));
      }

      var subKeys = new Array(40);
      var rho = 0x01010101;
      for(var i=0;i<20;i++){
        var A = h(i*2*rho, Me, k);
        var B = h((i*2+1)*rho, Mo, k);
        B = ((B<<8)|(B>>>24))>>>0;
        subKeys[2*i] = (A+B)>>>0;
        subKeys[2*i+1] = (((A+2*B)>>>0)<<9|((A+2*B)>>>0)>>>23)>>>0;
      }

      return {subKeys:subKeys, sBox:S, k:k};
    }

    function encryptBlock(input, off, output, ooff, key){
      var x0 = (input[off]|(input[off+1]<<8)|(input[off+2]<<16)|(input[off+3]<<24))>>>0;
      var x1 = (input[off+4]|(input[off+5]<<8)|(input[off+6]<<16)|(input[off+7]<<24))>>>0;
      var x2 = (input[off+8]|(input[off+9]<<8)|(input[off+10]<<16)|(input[off+11]<<24))>>>0;
      var x3 = (input[off+12]|(input[off+13]<<8)|(input[off+14]<<16)|(input[off+15]<<24))>>>0;

      x0 = (x0 ^ key.subKeys[0])>>>0;
      x1 = (x1 ^ key.subKeys[1])>>>0;
      x2 = (x2 ^ key.subKeys[2])>>>0;
      x3 = (x3 ^ key.subKeys[3])>>>0;

      for(var r=0;r<16;r+=2){
        var t0 = h(x0, key.sBox, key.k);
        var t1 = h(((x1<<8)|(x1>>>24))>>>0, key.sBox, key.k);
        x2 = (((x2^((t0+t1+key.subKeys[8+r*2])>>>0))>>>1)|((x2^((t0+t1+key.subKeys[8+r*2])>>>0))<<31))>>>0;
        x3 = ((((x3<<1)|(x3>>>31))^((t0+2*t1+key.subKeys[9+r*2])>>>0))>>>0);

        t0 = h(x2, key.sBox, key.k);
        t1 = h(((x3<<8)|(x3>>>24))>>>0, key.sBox, key.k);
        x0 = (((x0^((t0+t1+key.subKeys[8+(r+1)*2])>>>0))>>>1)|((x0^((t0+t1+key.subKeys[8+(r+1)*2])>>>0))<<31))>>>0;
        x1 = ((((x1<<1)|(x1>>>31))^((t0+2*t1+key.subKeys[9+(r+1)*2])>>>0))>>>0);
      }

      x2 = (x2 ^ key.subKeys[4])>>>0;
      x3 = (x3 ^ key.subKeys[5])>>>0;
      x0 = (x0 ^ key.subKeys[6])>>>0;
      x1 = (x1 ^ key.subKeys[7])>>>0;

      output[ooff] = x2&0xff; output[ooff+1]=(x2>>>8)&0xff; output[ooff+2]=(x2>>>16)&0xff; output[ooff+3]=(x2>>>24)&0xff;
      output[ooff+4] = x3&0xff; output[ooff+5]=(x3>>>8)&0xff; output[ooff+6]=(x3>>>16)&0xff; output[ooff+7]=(x3>>>24)&0xff;
      output[ooff+8] = x0&0xff; output[ooff+9]=(x0>>>8)&0xff; output[ooff+10]=(x0>>>16)&0xff; output[ooff+11]=(x0>>>24)&0xff;
      output[ooff+12] = x1&0xff; output[ooff+13]=(x1>>>8)&0xff; output[ooff+14]=(x1>>>16)&0xff; output[ooff+15]=(x1>>>24)&0xff;
    }

    return {makeKey:makeKey, encryptBlock:encryptBlock};
  })();

  /* ===== XChaCha20 Implementation ===== */
  var XChaCha20 = (function(){
    function quarterRound(s, a, b, c, d){
      s[a] = (s[a]+s[b])>>>0; s[d] = ((s[d]^s[a])>>>0); s[d] = ((s[d]<<16)|(s[d]>>>16))>>>0;
      s[c] = (s[c]+s[d])>>>0; s[b] = ((s[b]^s[c])>>>0); s[b] = ((s[b]<<12)|(s[b]>>>20))>>>0;
      s[a] = (s[a]+s[b])>>>0; s[d] = ((s[d]^s[a])>>>0); s[d] = ((s[d]<<8)|(s[d]>>>24))>>>0;
      s[c] = (s[c]+s[d])>>>0; s[b] = ((s[b]^s[c])>>>0); s[b] = ((s[b]<<7)|(s[b]>>>25))>>>0;
    }

    function chacha20Block(key, counter, nonce){
      var sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
      var state = new Uint32Array(16);
      state[0]=sigma[0]; state[1]=sigma[1]; state[2]=sigma[2]; state[3]=sigma[3];
      for(var i=0;i<8;i++) state[4+i]=key[i];
      state[12]=counter;
      state[13]=nonce[0]; state[14]=nonce[1]; state[15]=nonce[2];

      var working = new Uint32Array(state);
      for(var i=0;i<10;i++){
        quarterRound(working,0,4,8,12);
        quarterRound(working,1,5,9,13);
        quarterRound(working,2,6,10,14);
        quarterRound(working,3,7,11,15);
        quarterRound(working,0,5,10,15);
        quarterRound(working,1,6,11,12);
        quarterRound(working,2,7,8,13);
        quarterRound(working,3,4,9,14);
      }
      var out = new Uint32Array(16);
      for(var i=0;i<16;i++) out[i]=(working[i]+state[i])>>>0;
      return out;
    }

    function hchacha20(key, nonce16){
      // key: Uint32Array(8), nonce16: Uint8Array(16) -> first 16 bytes of 24-byte nonce
      var sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
      var state = new Uint32Array(16);
      state[0]=sigma[0]; state[1]=sigma[1]; state[2]=sigma[2]; state[3]=sigma[3];
      for(var i=0;i<8;i++) state[4+i]=key[i];
      // nonce as 4 uint32 LE
      for(var i=0;i<4;i++){
        state[12+i] = nonce16[i*4]|(nonce16[i*4+1]<<8)|(nonce16[i*4+2]<<16)|(nonce16[i*4+3]<<24);
      }

      var working = new Uint32Array(state);
      for(var i=0;i<10;i++){
        quarterRound(working,0,4,8,12);
        quarterRound(working,1,5,9,13);
        quarterRound(working,2,6,10,14);
        quarterRound(working,3,7,11,15);
        quarterRound(working,0,5,10,15);
        quarterRound(working,1,6,11,12);
        quarterRound(working,2,7,8,13);
        quarterRound(working,3,4,9,14);
      }
      // Return first 4 and last 4 words
      return new Uint32Array([working[0],working[1],working[2],working[3],working[12],working[13],working[14],working[15]]);
    }

    function decrypt(key32, nonce24, ciphertext){
      // XChaCha20: derive subkey with HChaCha20, then use ChaCha20 with derived key
      var keyWords = new Uint32Array(8);
      for(var i=0;i<8;i++){
        keyWords[i] = key32[i*4]|(key32[i*4+1]<<8)|(key32[i*4+2]<<16)|(key32[i*4+3]<<24);
      }

      // HChaCha20 with first 16 bytes of nonce
      var subKey = hchacha20(keyWords, nonce24.slice(0,16));

      // ChaCha20 nonce: 0x00000000 + last 8 bytes of original nonce
      var chachaNonce = new Uint32Array(3);
      chachaNonce[0] = 0;
      chachaNonce[1] = nonce24[16]|(nonce24[17]<<8)|(nonce24[18]<<16)|(nonce24[19]<<24);
      chachaNonce[2] = nonce24[20]|(nonce24[21]<<8)|(nonce24[22]<<16)|(nonce24[23]<<24);

      var out = new Uint8Array(ciphertext.length);
      var counter = 1; // XChaCha20-Poly1305 starts at counter 1 for message

      for(var offset=0; offset<ciphertext.length; offset+=64){
        var block = chacha20Block(subKey, counter, chachaNonce);
        var blockBytes = new Uint8Array(block.buffer);
        var end = Math.min(64, ciphertext.length - offset);
        for(var i=0;i<end;i++){
          out[offset+i] = ciphertext[offset+i] ^ blockBytes[i];
        }
        counter++;
      }
      return out;
    }

    return {decrypt:decrypt};
  })();

  /* ===== Decryption Keys ===== */
  var KEYS = {
    xchachaKey: b64decode("FjA662IaK9A3I4PhA/OD/OTrcrDo0VUNTlI7sseHkdQ="),
    twofishKey: b64decode("FontfP8KqSt+Jf2dI3+3mg91KDy5A/Ieg6I2fAXFGu0="),
    xorKeys: [
      b64decode("0Nj1/uAXex3/elH9s8VAGegoKNHfGAGPgMhEjm4i2HA="),
      b64decode("mgBtFuiBKsqcdMQzR4KkFiix/IFNrR/mUr0n0G0i35bOz10WvpEAdpEEHIQz+8jZdRYRZJVYnKYOdWI9WJN0IQ=="),
      b64decode("SWN7I7jHJ87BToYxHeLTCs0bZWYv9ZabRD6J4IMa6nOTWjEV9uR9F/ZTCjuU6xze"),
      b64decode("qoD5s7JZzU9IJ62/C59Vh5iUCiqY9S07/Qi677/D/ch3urULoaZDe8KqCeUj1paACb9k7e8eF7pwMYuV9vCHuYL5mJPuXxjaQ9FZPV+hyemPL2lj2yBHuZeJW9Oupb+OGiBsUVu1Xe5r8L7ISN0dv3IoUtOkEwNGh8cHxtD4jnw="),
      b64decode("18imdTNIOj3QyBDN1mdHUwocelBdaVFWAHd+gosP73/bzmI6QGRno6GZvWumu6VWBV8aWt25Kh5GH78q2ZU5ArEwqRUbk1e+mU7qS/jnq5N19aaCzCUQnWhmliTlQOqt"),
      b64decode("5ZUUe1L74pvmVZMeD6WcqrDGPHxyBFeTVir98Oe21LfwGe6PQ/bFj0DTpDqqCf2kCmI6QeKQJMSjAqAdZU5rlPboMkoUZiSA"),
      b64decode("Q+jyyUT53oS2BKZG3h9wjNjr/dT66eJxkFllkUygBB48mK3PuGXgP58riw+ON3ZvboOGgi+EcD4="),
      b64decode("p9QmtK3FW6YaHpRrGAA5jtm2vVP0ecg2KkX+U5C+3EWBgcpxGQtEcLA+CQGcuGtXzyYgcZNjvpSIXGPHapBYAKzLZFjvPJM/HBB422eVExEea+WQ165I0u009iyhyQePM4C4S3BXJtY=")
    ]
  };

  function b64decode(str){
    var raw = atob(str);
    var arr = new Uint8Array(raw.length);
    for(var i=0;i<raw.length;i++) arr[i]=raw.charCodeAt(i);
    return arr;
  }

  /* ===== Decryption Pipeline ===== */
  function rot13(str){
    return str.replace(/[A-Za-z]/g, function(c){
      var base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
    });
  }

  function xorBuffer(data, key){
    var out = new Uint8Array(data.length);
    for(var i=0;i<data.length;i++) out[i] = data[i] ^ key[i % key.length];
    return out;
  }

  function rotateBufferLeft(data, bits){
    var out = new Uint8Array(data.length);
    for(var i=0;i<data.length;i++) out[i] = ((data[i]<<bits)|(data[i]>>>(8-bits)))&0xff;
    return out;
  }

  function rotateBufferRight(data, bits){
    var out = new Uint8Array(data.length);
    for(var i=0;i<data.length;i++) out[i] = ((data[i]>>>bits)|(data[i]<<(8-bits)))&0xff;
    return out;
  }

  function multiXorDecrypt(data){
    var result = data;
    for(var i=KEYS.xorKeys.length-1; i>=0; i--){
      if(i%2===0){
        result = rotateBufferRight(result, (i+1)%8);
      } else {
        result = rotateBufferLeft(result, (i+1)%8);
      }
      result = xorBuffer(result, KEYS.xorKeys[i]);
    }
    return result;
  }

  function twofishDecryptCTR(data, keyBytes){
    if(data.length < 16) throw new Error("Twofish payload too short");
    var iv = data.slice(0, 16);
    var ciphertext = data.slice(16);
    var key = Twofish.makeKey(keyBytes);
    var out = new Uint8Array(ciphertext.length);
    var counter = new Uint8Array(iv);

    for(var i=0; i<ciphertext.length; i+=16){
      var block = new Uint8Array(16);
      Twofish.encryptBlock(counter, 0, block, 0, key);
      var end = Math.min(16, ciphertext.length - i);
      for(var j=0; j<end; j++){
        out[i+j] = ciphertext[i+j] ^ block[j];
      }
      // Increment counter
      for(var ci=15; ci>=0; ci--){
        counter[ci] = (counter[ci]+1)&0xff;
        if(counter[ci]) break;
      }
    }
    return out;
  }

  function decrypt(encryptedBase64){
    try {
      // Step 1: Base64 decode to text
      var text = new TextDecoder().decode(Uint8Array.from(atob(encryptedBase64), function(c){ return c.charCodeAt(0); }));
      // Step 2: ROT13
      var rotated = rot13(text);
      // Step 3: URL decode
      var decoded = decodeURIComponent(rotated);
      // Step 4: Base64 decode to binary
      var binary = Uint8Array.from(atob(decoded), function(c){ return c.charCodeAt(0); });
      // Step 5: Twofish CTR decrypt
      var tfDecrypted = twofishDecryptCTR(binary, KEYS.twofishKey);
      // Step 6: Multi-XOR decrypt
      var xorDecrypted = multiXorDecrypt(tfDecrypted);
      // Step 7: XChaCha20 decrypt (first 24 bytes = nonce)
      var nonce = xorDecrypted.slice(0, 24);
      var ciphertext = xorDecrypted.slice(24);
      var plaintext = XChaCha20.decrypt(KEYS.xchachaKey, nonce, ciphertext);
      // Parse JSON
      var jsonStr = new TextDecoder().decode(plaintext);
      return JSON.parse(jsonStr);
    } catch(e){
      console.error("1anime decrypt error:", e);
      return null;
    }
  }

  /* ===== API Functions ===== */
  function generateRequestId(){
    var r = Date.now().toString(36) + Math.random().toString(36).slice(2,12);
    return "watch-" + r;
  }

  function getEpisodes(anilistId, callback){
    console.log("[1ANIME][getEpisodes] anilistId="+anilistId+" url="+BASE+"/api/episodes-id?id="+anilistId);
    $ap(BASE + "/api/episodes-id?id=" + anilistId, function(r){
      console.log("[1ANIME][getEpisodes][RESP] ok="+r.ok+" status="+r.status+" responseLen="+(r.responseText?r.responseText.length:0));
      if(r.ok){
        try {
          var data = JSON.parse(r.responseText);
          console.log("[1ANIME][getEpisodes][OK] episodes="+(data&&data.episodes?data.episodes.length:'none'));
          callback(data);
        } catch(e){
          console.error("[1ANIME][getEpisodes][PARSE_ERR]:", e);
          callback(null);
        }
      } else {
        console.log("[1ANIME][getEpisodes][FAIL] responseText="+(r.responseText?r.responseText.substring(0,200):'empty'));
        callback(null);
      }
    });
  }

  function getStream(anilistId, episode, provider, lang, callback){
    var rid = generateRequestId();
    var url = BASE + "/api/stream?anilistId=" + encodeURIComponent(anilistId) +
      "&providerName=" + encodeURIComponent(provider) +
      "&episodeNumber=" + encodeURIComponent(episode) +
      "&subOrDub=" + encodeURIComponent(lang) +
      "&rid=" + encodeURIComponent(rid);

    $ap(url, function(r){
      if(r.ok){
        try {
          var data = JSON.parse(r.responseText);
          if(data && data.result){
            var decrypted = decrypt(data.result);
            callback(decrypted);
          } else {
            callback(null);
          }
        } catch(e){
          console.error("1anime stream error:", e);
          callback(null);
        }
      } else {
        callback(null);
      }
    }, {"x-watch-request-id": rid});
  }

  function loadVideo(dt, f){
    var oe = dt.ep[dt.epactive];
    var epNum = oe.ep || oe.number || (dt.epactive+1);
    var anilistId = dt.anilist_id || dt.url;
    var subtype = "sub";
    var originalSubtype = "sub";

    // Determine sub/dub preference
    if(_API.currentStreamType==2 || pb.cfg_data.prefstream==2){
      if(oe.dub) subtype = "dub";
      originalSubtype = "dub";
    }

    dt.streamtype = (subtype=="dub") ? "dub" : "sub";
    dt.servers = dt.servers || {};
    dt.servers['sub'] = [pb.serverobj('1anime-sub',0)];
    if(oe.dub){
      dt.servers['dub'] = [pb.serverobj('1anime-dub',0)];
    }

    pb.updateStreamTypeInfo();

    var providerIdx = 0;
    function tryProvider(){
      if(providerIdx >= PROVIDERS.length){
        /* All providers exhausted for current subtype - try fallback stream type */
        var fallbackType = (subtype == "dub") ? "sub" : (oe.dub ? "dub" : null);
        if(fallbackType && fallbackType != originalSubtype + "_tried"){
          var prevType = subtype;
          subtype = fallbackType;
          originalSubtype = originalSubtype + "_tried"; /* prevent infinite loop */
          dt.streamtype = (subtype=="dub") ? "dub" : "sub";
          providerIdx = 0;
          console.log("1anime: " + prevType.toUpperCase() + " unavailable, falling back to " + subtype.toUpperCase());
          _API.showToast(prevType.toUpperCase() + " unavailable. Switched to " + subtype.toUpperCase());
          pb.updateStreamTypeInfo();
          tryProvider();
          return;
        }
        f(null);
        return;
      }
      var prov = PROVIDERS[providerIdx];
      console.log("1anime: trying provider " + prov + " for ep " + epNum + " (" + subtype + ")");

      getStream(anilistId, epNum, prov, subtype=="dub"?"d":"s", function(result){
        if(result && result.sources && result.sources.length > 0){
          currentProvider = prov;
          f({
            d: result,
            s: null,
            provider: prov
          });
        } else {
          providerIdx++;
          tryProvider();
        }
      });
    }

    // Try preferred provider first
    var prefIdx = PROVIDERS.indexOf(currentProvider);
    if(prefIdx > 0){
      // Move preferred to front
      PROVIDERS.splice(prefIdx, 1);
      PROVIDERS.unshift(currentProvider);
    }
    tryProvider();
  }

  /* ===== View/Episode Parsing ===== */
  function getAnimeId(url){
    // URL format: anilistId#epNumber
    var parts = url.split('#');
    return parts[0];
  }

  function getView(url, f){
    var uid = ++_API.viewid;
    var parts = url.split('#');
    var anilistId = parts[0];
    var epNum = parts.length > 1 ? parseInt(parts[1]) : 1;

    getEpisodes(anilistId, function(data){
      if(!data || !data.episodes || data.episodes.length === 0){
        f({status:false}, uid);
        return;
      }

      var eps = data.episodes;
      var epList = [];
      for(var i=0; i<eps.length; i++){
        var ep = eps[i];
        epList.push({
          ep: ep.number || (i+1),
          title: ep.title || ("Episode " + (ep.number || (i+1))),
          url: anilistId + '#' + (ep.number || (i+1)),
          sub: ep.sub ? 1 : 0,
          dub: ep.dub ? 1 : 0,
          img: ep.image || ''
        });
      }

      var result = {
        status: true,
        url: url,
        anilist_id: anilistId,
        ep: epList,
        epactive: Math.max(0, epNum - 1),
        title: '',
        poster: '',
        genres: [],
        desc: ''
      };

      f(result, uid);
    });
  }

  function getTooltip(id, cb, url, isview){
    // Use AniList GraphQL for tooltip data
    var anilistId = id;
    if(url){
      anilistId = getAnimeId(url);
    }
    if(!anilistId){
      cb(null);
      return;
    }

    var query = '{"query":"query{Media(id:'+anilistId+',type:ANIME){id idMal title{romaji english native}description status episodes genres averageScore coverImage{extraLarge large}bannerImage startDate{year month day}}}"}';

    $a("/__proxy/https://graphql.anilist.co/", function(r){
      if(r.ok){
        try{
          var data = JSON.parse(r.responseText);
          var media = data.data.Media;
          cb({
            title: media.title.english || media.title.romaji || '',
            poster: media.coverImage.extraLarge || media.coverImage.large || '',
            banner: media.bannerImage || '',
            desc: media.description || '',
            genres: media.genres || [],
            status: media.status || '',
            episodes: media.episodes || 0,
            score: media.averageScore || 0,
            malId: media.idMal,
            anilistId: media.id
          });
        }catch(e){
          cb(null);
        }
      } else {
        cb(null);
      }
    }, {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      post: query
    });
  }

  function getFilterOrigin(){
    return BASE;
  }

  function getFilterUrl(q, genres, sort, page, ses, year){
    // Use AniList search
    return null; // Will use AniList search instead
  }

  function getHomepage(callback){
    // Use AniList for homepage data
    callback([]);
  }

  function recentParse(responseText){
    // Parse AniList trending/recent
    try{
      var data = JSON.parse(responseText);
      if(data && data.data && data.data.Page){
        var media = data.data.Page.media;
        var results = [];
        for(var i=0;i<media.length;i++){
          var m = media[i];
          results.push({
            title: m.title.english || m.title.romaji || '',
            url: m.id + '#1',
            poster: m.coverImage.extraLarge || m.coverImage.large || '',
            sub: 1,
            dub: 0,
            ep: m.episodes || '?'
          });
        }
        return results;
      }
    }catch(e){}
    return [];
  }

  /* ===== Public API ===== */
  return {
    BASE: BASE,
    PROVIDERS: PROVIDERS,
    currentProvider: currentProvider,
    getEpisodes: getEpisodes,
    getStream: getStream,
    loadVideo: loadVideo,
    decrypt: decrypt,
    getAnimeId: getAnimeId,
    getView: getView,
    getTooltip: getTooltip,
    getFilterOrigin: getFilterOrigin,
    getFilterUrl: getFilterUrl,
    getHomepage: getHomepage,
    recentParse: recentParse,
    setProvider: function(p){ currentProvider = p; }
  };
})();
