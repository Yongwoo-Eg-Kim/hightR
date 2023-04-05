# Please refer to the original paper for details: "Hong, D., Sung, J., Hong, S., Lim, J., Lee, S., Koo, B. S., ... & Chee, S. (2006). HIGHT: A new block cipher suitable for low-resource device. In Cryptographic Hardware and Embedded Systems-CHES 2006: 8th International Workshop, Yokohama, Japan, October 10-13, 2006. Proceedings 8 (pp. 46-59). Springer Berlin Heidelberg."
# Original Paper url: https://www.iacr.org/archive/ches2006/04/04.pdf

# OTHER REFERENCES
# https://seed.kisa.or.kr/kisa/algorithm/EgovHightInfo.do
# https://seed.kisa.or.kr/kisa/Board/18/detailView.do

utils::globalVariables(c("P"))

list_to_byte <- function(lst) {
  byte =0
  for (bit in lst){
    byte = bitwOr(bitwShiftL(byte,1), bit)
  }
  return(byte)
}

#list_to_byte( c(1,1,0,0,1,1,1,1,1))

rotate_bits <- function(x,n) {
  return (
    bitwOr (bitwShiftL(x,n) %% 256  , bitwShiftR(x,8-n) )
  )
}

#rotate_bits(7700,2)


whitening_key_generation <- function(MK){
  WK = c()
  for (i in c(1:4) ) {
    WK[i] = MK[i + 12]
    WK[i + 4] = MK[i]
  }
    return (WK)
}
#whitening_key_generation( c(1,9,7,1,1,2,3,1,1,1,1,1,1,1,9,1,1,1,1))



constant_generation <- function() {
  s <- c(0, 1, 0, 1, 1, 0, 1)
  delta <- list_to_byte(rev(s))
  for (i in c(2:128)) {
    s <- append(s, bitwXor( (s[i+2]) , (s[i-1]) ) )
    delta <- append(delta, list_to_byte(rev( na.omit(s[i:(i+7) ])  )))
  }
  return(delta)
}


subkey_generation <- function(delta, MK) {
  SK =c()
  for (i in c(0:7)){
    for (j in c(0:7)){
      SK[16*i+j+1] = (MK[(j - i)%% 8 +1] + delta[16 * i + j +1]) %% 256
    }
    for (j in c(0:7)){
      SK[16 * i + j+1 + 8] =(MK[(j - i) %% 8 + 8+1] + delta[16 * i + j + 8+1]) %% 256
    }
  }
  return (SK)
}

#delta=constant_generation()
#MK = c( 1,9,7,1,1,2,3,1,1,1,1,1,1,1,9,1,1,1,1)
#subkey_generation(delta,MK)



encryption_key_schedule <- function(MK){
  delta = constant_generation()
  WK = whitening_key_generation(MK)
  SK = subkey_generation(delta, MK)
  return (list(WK, SK))
}
#encryption_key_schedule(MK)


 decryption_key_schedule <- function(MK) {
   delta = constant_generation()
   WK = whitening_key_generation(MK)
   SK = rev(subkey_generation(delta, MK))
   return (list( WK, SK))

 }
#decryption_key_schedule(MK)



encryption_initial_transformation <- function(P, WK){
    X_0 = c(
      (P[1] + WK[1]) %% 256,
      P[2],
      bitwXor(P[3], WK[2]),
      P[4],
      (P[5] + WK[3]) %% 256,
      P[6],
      bitwXor(P[7] , WK[4]),
      P[8]
    )
  return (X_0)
}
#WK = whitening_key_generation(MK)
#encryption_initial_transformation( c(1,2,3,4,5,7,77,99) , WK)




decryption_initial_transformation <- function(C, WK){
  X_0 = c(
    C[8],
    (C[1] - WK[5]) %% 256,
    C[2],
    bitwXor( C[3] , WK[6]),
    C[4],
    (C[5] - WK[7]) %% 256,
    C[6],
    bitwXor(C[7] , WK[8])
  )
  return (X_0)
}
#WK = whitening_key_generation(MK)
#decryption_initial_transformation(c(7,77,777,7777,1,2,3,4), WK)




f_0 <- function(x){
  return ( bitwXor(bitwXor(rotate_bits(x,1) ,rotate_bits(x,2)) ,rotate_bits(x,7)) )
}


f_1 <-function(x){
  return ( bitwXor(bitwXor(rotate_bits(x,3) , rotate_bits(x,4) ), rotate_bits(x,6) ))
}



encryption_round_function <- function(i, X_i, SK){
  X_j = c(
    bitwXor(X_i[8], (((f_0(X_i[7])) + SK[4 * i + 3+1]) %% 256) ),
    X_i[1],
    (X_i[2] + bitwXor(f_1(X_i[1]) , SK[4 * i +1])) %% 256,
    X_i[3],
    bitwXor(X_i[4], (((f_0(X_i[3])) + SK[4 * i + 1+1]) %% 256)),
    X_i[5],
    (X_i[6] + bitwXor(f_1(X_i[5]) , SK[4 * i + 2+1])) %% 256,
    X_i[7]
  )
return (X_j)
}
#SK = subkey_generation(delta, MK)
#encryption_round_function(3, c(1,2,3,4,5,6,7,8), SK)



decryption_round_function <- function(i, X_i, SK){
  X_j = c(
    X_i[2],
    (X_i[3] - bitwXor(f_1(X_i[2]) , SK[4 * i + 3+1])) %% 256,
    X_i[4],
    bitwXor(X_i[5] , ((f_0(X_i[4]) + SK[4 * i + 2+1]) %% 256)),
    X_i[6],
    (X_i[7] - bitwXor(f_1(X_i[6]) , SK[4 * i + 1+1])) %% 256,
    X_i[8],
    bitwXor(X_i[1], ((f_0(X_i[8]) + SK[4 * i+1]) %% 256))
  )
return (X_j)
}
#decryption_round_function(3, c(1,2,3,4,5,6,7,8), SK)


encryption_final_transformation <- function(X_32, WK){
  C = c(
    (X_32[2] + WK[5]) %% 256,
    X_32[3],
    bitwXor( X_32[4] , WK[6]),
    X_32[5],
    (X_32[6] + WK[7]) %% 256,
    X_32[7],
    bitwXor(X_32[8] , WK[8]),
    X_32[1]
  )
return (C)
}
#encryption_final_transformation (c(7,1,3,2,4,5,6,7), WK)


decryption_final_transformation <- function(X_32, WK){
  D = c(
    (X_32[1] - WK[1]) %% 256,
    X_32[2],
    bitwXor(X_32[3], WK[2]),
    X_32[4],
    (X_32[5] - WK[3]) %% 256,
    X_32[6],
    bitwXor(X_32[7] , WK[4]),
    X_32[8]
)
return (D)
}
#decryption_final_transformation (c(7,1,3,2,4,5,6,7), WK)



encryption_transformation <- function(P, WK, SK){
  X_i = encryption_initial_transformation(P, WK)
  for (i in c(0:31)){
    X_i = encryption_round_function(i, X_i, SK)}
  C = encryption_final_transformation(X_i, WK)
  return (C)
}
#encryption_transformation(c(7,1,3,2,4,5,6,7), WK, SK)



decryption_transformation <- function(C, WK, SK){
  X_i = decryption_initial_transformation(C, WK)
  for (i in c(0:31)){
    X_i = decryption_round_function(i, X_i, SK) }
  D = decryption_final_transformation(X_i, WK)
  return (D)
}
#decryption_transformation(c(7,1,3,2,4,5,6,7), WK, SK)


ecb_hight_encryption <-function(P, MK,output_format='int'){
  WK = encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  C = encryption_transformation(P, WK, SK)
  if (length(P)>8) {
    for (block in seq(8, length(P)-1,by= 8)){
     C = append(C, encryption_transformation(P[(block+1):(block + 8)] , WK, SK))
      }
  }
  return (C)
}


ecb_hight_decryption <- function(C, MK,output_format='int'){
  WK = decryption_key_schedule(MK)[[1]]
  SK= decryption_key_schedule(MK)[[2]]
  D = decryption_transformation(as.integer(C), WK, SK)
  if(length(C) > 8) {
    for (block in seq(8, length(P)-1,by= 8)){
      D = append(D, decryption_transformation(C[(block+1):(block +8)], WK, SK))
    }
  }
  return (D)
}



cbc_hight_encryption <- function(P, IV, MK){
  WK= encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  C = encryption_transformation(bitwXor(P[1:8],IV), WK, SK)
  if (length(P)>8) {
    for (block in seq(8, length(P)-1,by= 8)){
      C = append(C,encryption_transformation(bitwXor( P[(block+1):(block + 8)] ,C[(block - 8+1):block] ) , WK, SK))
    }
  }
return (c(na.omit(C)))
}


cfb_hight_encryption <- function(P, IV, MK){
  WK= encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  C= bitwXor(P[1:8] , encryption_transformation(IV,WK,SK) )
  if (length(P)>8) {
    for (block in seq(8, length(P)-1,by= 8)){
      C = append(C, bitwXor(encryption_transformation(C[(block - 8+1):block],WK,SK), P[(block+1):(block + 8)]  ) )
    }
  }
  return (c(na.omit(C)))
}

ofb_hight_encryption <- function(P, IV, MK){
  WK= encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  e_IV=encryption_transformation(IV,WK,SK)
  C= bitwXor(P[1:8] , e_IV )
  if (length(P)>8) {
    for (block in seq(8, length(P)-1,by= 8)){
      e_IV = encryption_transformation(e_IV, WK, SK)
      C = append(C, bitwXor(e_IV, P[(block+1):(block + 8)]  ) )
    }
  }
  return (c(na.omit(C)))
}





cbc_hight_decryption <- function(C, IV, MK){
  WK= decryption_key_schedule(MK)[[1]]
  SK = decryption_key_schedule(MK)[[2]]
  D= bitwXor( decryption_transformation(as.integer(C[1:8]) ,WK, SK), IV)
  if (length(C)>8) {
    for (block in seq(8, length(C)-1,by = 8) ){
      D = append(D, bitwXor(decryption_transformation( C[(block+1):(block + 8)], WK, SK), C[(block - 8+1):block]))
    }
  }
  return (D)
}

cfb_hight_decryption <- function(C, IV, MK){
  WK= encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  D= bitwXor(as.integer(C[1:8]) , encryption_transformation(IV,WK,SK) )
  if (length(C)>8) {
    for (block in seq(8, length(C)-1,by = 8) ){
      D = append(D, bitwXor(encryption_transformation( C[(block-8+1):(block)], WK, SK), C[(block+1):(block+8)]))
    }
  }
  return (D)
}

ofb_hight_decryption <- function(C, IV, MK){
  WK= encryption_key_schedule(MK)[[1]]
  SK = encryption_key_schedule(MK)[[2]]
  e_IV=encryption_transformation(IV,WK,SK)
  D= bitwXor(as.integer(C[1:8]) , e_IV)
  if (length(C)>8) {
    for (block in seq(8, length(C)-1,by = 8) ){
      e_IV = encryption_transformation(e_IV, WK, SK)
      D = append(D, bitwXor(e_IV, C[(block+1):(block+8)]))
    }
  }
  return (D)
}







#
#
# MK = c(0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89)
# IV = c(0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81)
# P = c(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
# #P = c(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
# cbc_hight_encryption(P, IV, MK)
# cbc_hight_decryption(cbc_hight_encryption(P, IV, MK),IV, MK)
# P
#
# cfb_hight_encryption(P, IV, MK)
# cfb_hight_decryption(cfb_hight_encryption(P, IV, MK), IV, MK)
# P
#
#
# ecb_hight_encryption(P, MK)
# ecb_hight_decryption(ecb_hight_encryption(P, MK), MK)
# P
#
#
#
# ofb_hight_encryption(P, IV, MK)
# ofb_hight_decryption(ofb_hight_encryption(P,IV, MK),IV ,  MK)
# P
#
#
# hight_enc(P,IV,MK,mode = 'ofb', output='int')
# hight_enc(P,IV,MK,mode = 'cbc', output='hex')
# hight_dec (hight_enc(P,IV,MK,mode = 'cbc', output='int') , IV, MK , 'cbc','int')


