#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Functions
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

#' @title
#' Perform encryption using HIGHT.
#'
#' @description
#' HIGHT (HIGh security and light weigHT) is a symmetric key block cipher algorithm designed for use in resource-constrained environments such as embedded systems and wireless sensor networks.
#' Outputs 64-bit ciphertext from 128-bit master key and 64-bit plaintext. This process can be repeated multiple times.
#'
#' @import "stats"
#'
#' @references
#' Hong, D., Sung, J., Hong, S., Lim, J., Lee, S., Koo, B. S., ... & Chee, S. (2006). HIGHT: A new block cipher suitable for low-resource device. In Cryptographic Hardware and Embedded Systems-CHES 2006: 8th International Workshop, Yokohama, Japan, October 10-13, 2006. Proceedings 8 (pp. 46-59). Springer Berlin Heidelberg.
#'
#' @name hight_enc
#'
#' @param P Plaintext. Its length must be a multiple of 8 and must have a value from 0 to 255.
#' @param MK Master Key. This is used to encrypt other keys that are used to encrypt and decrypt data. This should be typically kept secret and is only accessible to authorized users who need to use it for encryption and decryption operations. It should have a length of 16 and must have a value from 0 to 255.
#' @param mode Please select one from 'ECB'(Electric CodeBook mode),'CFB'(Cipher FeedBack mode),'CBC'(Cipher Block Chaining mode),'OFB'(Output FeedBack mode).
#' @param IV Initialization Vector. The IV is usually generated randomly and is different for each encryption operation. It is combined with the encryption key to produce a unique key for each encryption operation. Its length must be equal to 8, which is a unit of cryptographic block, and the value range must also have a value from 0 to 255. This parameter will be ignored in ECB mode.
#' @param output Support 'hex'(e.g. '0x66') string or 'int'(e.g. 102) for output format.
#'
#' @return  Returns a numeric vector encrypted by the HIGHT algorithm.
#'
#' @examples
#' # Encryption (CBC mode)
#' MK = c(0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
#'        0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89)
#' IV = c(0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81)
#' P = c(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
#' C = hight_enc(P, MK, mode = 'CBC', IV, output='int')
#' print(C)
#'
#' # Encryption (ECB mode)
#' MK = c(0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1,
#'        0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89)
#' # IV is not used in ECB mode.
#' P = c(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
#' C = hight_enc(P, MK, mode = 'ECB',  output='int')
#' print(C)
#'
#'
#'
#'
#' @rdname hight_enc
#' @export



hight_enc <- function(P, MK, mode, IV=NULL, output='int' ){
  if( (length(IV)  != 8) & (mode!='ecb') & (mode!='ECB') ) { stop(paste('Please check the length of IV(Initialization Vector) parameter' , IV,sep=': ')) }
  if( !all( (IV >=0) & (IV <=255) ) & (mode!='ecb')& (mode!='ECB') ) { stop(paste('Please check the range of IV(Initialization Vector) parameter'), IV,sep=': ') }
  if( length(P)  %% 8 != 0  ) {  stop(paste('Please check the length of P(Plaintext) parameter', P,sep=': ')) }
  if( !all( (P >=0) & (P <=255)) ) {  stop(paste('Please check the range of P(Plaintext) parameter', P,sep=': ')) }
  if (length(MK) != 16) { stop(paste('Please check the length of MK(MasterKey) parameter',MK,sep=': '))}
  if( !all( (MK >=0) & (MK <=255)) ) { stop(paste('Please check the range of MK(MasterKey) parameter',MK,sep=': ')) }

  if (mode %in% c('cbc','CBC')) {
    result = cbc_hight_encryption(P,IV,MK)
  }
  else if (mode  %in% c('cfb','CFB')) {
    result = cfb_hight_encryption(P, IV, MK)
  }
  else if (mode  %in% c('ecb','ECB' )) {
    result = ecb_hight_encryption(P, MK)
  }
  else if (mode  %in% c('ofb','OFB') ) {
    result = ofb_hight_encryption(P, IV, MK)
  }
  else {
    stop(paste('Stopping, Please check the mode parameter' ,mode ,sep=': '));

  }

  '%ni%' <- Negate('%in%')
  if (output=='int') {return (result)}
  if (output=='hex') {return (sprintf("0X%X",result))}
  if (output %ni% c('hex','int')) {
    stop(paste('Please check the output parameter', output,sep=': '))
    }
}
