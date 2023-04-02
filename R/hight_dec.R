#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Functions
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#' @title
#' Perform decryption using HIGHT.
#'
#' @description
#' HIGHT (HIGh security and light weigHT) is a symmetric key block cipher algorithm designed for use in resource-constrained environments such as embedded systems and wireless sensor networks.
#' Outputs 64-bit ciphertext from 128-bit master key and 64-bit plaintext.
#'
#' @references
#' Hong, D., Sung, J., Hong, S., Lim, J., Lee, S., Koo, B. S., ... & Chee, S. (2006). HIGHT: A new block cipher suitable for low-resource device. In Cryptographic Hardware and Embedded Systems-CHES 2006: 8th International Workshop, Yokohama, Japan, October 10-13, 2006. Proceedings 8 (pp. 46-59). Springer Berlin Heidelberg.
#'
#' @import "stats"
#'
#' @name hight_dec
#'
#' @param C Encrypted plaintext by HIGHT.
#' @param IV Initialization Vector. The IV is usually generated randomly and is different for each encryption operation. It is combined with the encryption key to produce a unique key for each encryption operation. Its length must be equal to 8, which is a unit of cryptographic block, and the value range must also have a value from 0 to 255.
#' @param MK Master Key. This is used to encrypt other keys that are used to encrypt and decrypt data. This should be typically kept secret and is only accessible to authorized users who need to use it for encryption and decryption operations.  It should have a length of 16 and must have a value from 0 to 255.
#' @param mode Please select one from 'ecb'(Electric CodeBook mode),'cfb'(Cipher FeedBack mode),'cbc'(Cipher Block Chaining mode),'ofb'(Output FeedBack mode).
#' @param output Support 'hex'(e.g. '0x66') string or 'int'(e.g. 102) for output format.
#' @examples
#' MK = c(0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
#'        0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89)
#' IV = c(0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81)
#' P = c(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
#' C=hight_enc(P,IV,MK,mode = 'cbc', output='int')
#' hight_dec (C, IV, MK , mode = 'cbc', output = 'int')
#'
#' @rdname hight_dec
#' @export

hight_dec <- function(C, IV, MK, mode, output='int' ){
  if( length(IV)  != 8  ) { stop('Please check the length of Initialization Vector(IV)') }
  if( !all( (IV >=0) & (IV <=255)) ) { stop('Please check the range of Initialization Vector(IV)') }
  if( length(C)  %% 8 != 0  ) { stop('Please check the length of Password') }
  if( !all( (C >=0) & (C <=255)) ) { stop('Please check the range of Password') }
  if (length(MK) != 16) { stop('Please check the length of MasterKey(MK)')}
  if( !all( (MK >=0) & (MK <=255)) ) { stop('Please check the range of MasterKey(MK)') }
  C = as.integer(C)

  if (mode=='cbc') {
    result = cbc_hight_decryption(C,IV,MK)
  }
  else if (mode =='cfb') {
    result = cfb_hight_decryption(C, IV, MK)
  }
  else if (mode =='ecb' ) {
    result = ecb_hight_decryption(C, MK)
  }
  else if (mode =='ofb' ) {
    result = ofb_hight_decryption(C, IV, MK)
  }
  else {
    stop('Stopping, Please check the mode.')
  }

  '%ni%' <- Negate('%in%')
  if (output=='int') {return (result)}
  if (output=='hex') {return (sprintf("0X%X",result))}
  if (output %ni% c('hex','int')) { print('Please check the output')}
}
