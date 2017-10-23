/*********************************************************************************************
* Name         : DES.js
* Description  : Javascript implementation of the DES encryption algorithm
* Version      : 1.0
* License      : GPL 3.0
* Author       : Alvaro Fernandez (nishinishi)
* Contact mail : nishinishi9999@gmail.com
*********************************************************************************************/

/*********************************************************************************************
* Contants (var)
*
*   - Permutation tables
*       - initial_table
*       - initial_table_L
*       - initial_table_R
*       - final_table
*       - parity_drop_table
*       - expansion_table
*       - compression_table
*       - straight_table
*       - inverse_straight_table
*       - s_box_table
*       - shift_table
*       - shift_offset
*
*
*
* Global variables
*
*   - Arrays
*       - K
*   
*
*
* Functions
*
*   - Utility functions:
*       - bin_arr_to_ascii()
*       - bin_arr_to_hex()
*       - hex_to_bin_arr()
*       - ascii_to_bin_arr()
*
*   - DES:
*       - gen_round_keys()
*       - cipher()
*       - encrypt()
*       - decrypt()
*
*********************************************************************************************/

// var btoa = require('btoa'); // For nodejs testing


/***************************
* Initial permutation (IP)
***************************/
var initial_table =
    [
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16,  8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ];


/*************************************
* Left side Initial permutation (IP)
*************************************/
var initial_table_L =
    [
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ];


/*****************************************
* Right side of Initial permutation (IP)
*****************************************/
var initial_table_R =
    [
        56, 48, 40, 32, 24, 16,  8, 0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6
    ];


/***************************
* Final permutation (IP-1)
***************************/
var final_table =
    [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25,
        32, 0, 40,  8, 48, 16, 56, 24
    ];


/***********************************************
* Expansion table (E) used in the DES function
* to expand R from 32 bits to 48
***********************************************/
var expansion_table =
    [
         31,  0,  1,  2,  3,  4,
          3,  4,  5,  6,  7,  8,
          7,  8,  9, 10, 11, 12,
         11, 12, 13, 14, 15, 16,
         15, 16, 17, 18, 19, 20,
         19, 20, 21, 22, 23, 24,
         23, 24, 25, 26, 27, 28,
         27, 28, 29, 30, 31,  0
    ];


/*************************************************
* Parity drop table used to contract the key
* from 64 bits to 56 and to permutate the result
*************************************************/
var parity_drop_table =
    [
        56, 48, 40, 32, 24, 16,  8,  0,
        57, 49, 41, 33, 25, 17,  9,  1,
        58, 50, 42, 34, 26, 18, 10,  2,
        59, 51, 43, 35, 62, 54, 46, 38,
        30, 22, 14,  6, 61, 53, 45, 37,
        29, 21, 13,  5, 60, 52, 44, 36,
        28, 20, 12,  4, 27, 19, 11,  3
    ];


/************************************************
* Compression table used to contract round keys
* from 56 bits to 48 bits
************************************************/
var compression_table =
    [
        13, 16, 10, 23,  0,  4,  2, 27,
        14,  5, 20,  9, 22, 18, 11,  3,
        25,  7, 15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54, 29, 39,
        50, 44, 32, 47, 43, 48, 38, 55,
        33, 52, 45, 41, 49, 35, 28, 31
    ];


/*********************************************
* Permutation table applied to s_box results
*********************************************/
var straight_table =
    [
        15,  6, 19, 20, 28, 11, 27, 16,
         0, 14, 22, 25,  4, 17, 30,  9,
         1,  7, 23, 13, 31, 26,  2,  8,
        18, 12, 29,  5, 21, 10,  3, 24
    ];


/****************************************************
* Inverse table of straight_table for speed reasons
****************************************************/
var inverse_straight_table =
    [
         8, 16, 22, 30, 12, 27,  1, 17,
        23, 15, 29,  5, 25, 19,  9,  0,
         7, 13, 24,  2,  3, 28, 10, 18,
        31, 11, 21,  6,  4, 26, 14, 20
    ];


/******************************************
* S-Box tables, the core of the algorithm
******************************************/
var s_box_table =
    [
        /**** s-box 0 ****/
        [
            [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
            [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
            [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
            [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
        ],
        
        /**** s-box 1 *****/
        [
            [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
            [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
            [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
            [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
        ],

        /**** s-box 2 ****/
        [
            [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
            [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
            [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
            [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
        ],
        
        /**** s-box 3 ****/
        [
            [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
            [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
            [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
            [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
        ],
        
        /**** s-box 4 ****/
        [
            [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
            [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
            [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
            [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
        ],
        
        /**** s-box 5 ****/
        [
            [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
            [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
            [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
            [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
        ],
        
        /**** s-box 6 ****/
        [
            [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
            [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
            [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
            [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
        ],
        
        /**** s-box 7 ****/
        [
            [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
            [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
            [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
            [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
        ]
    ];


/********************************************************************
* Number of left shifts to apply in each round key generation round
* and precalculated offset for speed reasons
********************************************************************/
var shift_table  = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
var shift_offset = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];


//---- Functions ---------------------------------------------------------------------------------------------------

/**************************************************************************
* Description : bin_arr_to_ascii() - Convert binary array to ascii string
* Takes       : bin   (arrayref) - 64-length binary array
* Returns     : ascii (string)   - 8 byte string
* Notes       : Nothing
* TODO        : Nothing
**************************************************************************/
function bin_arr_to_ascii(bin)
    {
        var ascii = '';
        
        for(var n = 0, c = 0; n < 64; n += 8)
            {
                c = (bin[n]   << 7)
                  + (bin[n+1] << 6)
                  + (bin[n+2] << 5)
                  + (bin[n+3] << 4)
                  + (bin[n+4] << 3)
                  + (bin[n+5] << 2)
                  + (bin[n+6] << 1)
                  + (bin[n+7] << 0);
                
                ascii += String.fromCharCode(c);
            }

        return ascii;
    }


/******************************************************************************
* Description : bin_arr_to_hex() - Convert binary array to hexadecimal string
* Takes       : bin (arrayref)   - 64-length binary array
* Returns     : hex_str (string) - 16 length left-padded hexadecimal string
* Notes       : Nothing
* TODO        : Nothing
******************************************************************************/
function bin_arr_to_hex(bin)
    {
        var hex_str = '';
        var hex;
        var pos;
        var dec;
        
        for(var n = 0; n < 8; n++)
            {
                pos = n*8;
                
                dec = (bin[pos]   << 7)
                    + (bin[pos+1] << 6)
                    + (bin[pos+2] << 5)
                    + (bin[pos+3] << 4)
                    + (bin[pos+4] << 3)
                    + (bin[pos+5] << 2)
                    + (bin[pos+6] << 1)
                    + (bin[pos+7] << 0);

                hex = dec.toString(16);
                
                
                /**************
                * Add padding
                **************/
                if(hex.length == 1) { hex = '0'+hex; }
                
                
                hex_str += hex;
            }

        return hex_str;
    }


/*************************************************************************************
* Description : hex_to_bin_arr(hex_str) - Convert hexadecimal string to binary array
* Takes       : hex_str (string) - 16-length hexadecimal string
* Returns     : bin (arrayref)   - 64-length binary array
* Notes       : Nothing
* TODO        : Nothing
*************************************************************************************/
function hex_to_bin_arr(hex_str)
    {
        var n, m;
        var hex;
        var row;
        var pos;
        
        var bin = new Array(64);
        
        
        /*******************************
        * Remove starting 0x if exists
        *******************************/
        if(hex_str.match(/^0x/i)) { hex_str = hex_str.substr(2); }
        
                        
        for(n = 0; n < 8; n++)
            {
                /***************************************
                * Get two chars and convert to decimal
                ***************************************/
                pos = n*2;
                hex = parseInt(hex_str[pos] + hex_str[pos+1], 16);
                        
                row = n*8;
                for(m = 0; m < 8; m++)
                    {
                        bin[row + m] = ( hex >> (7-m) ) & 1;
                    }
            }

        
        return bin;
    }


/**************************************************************************
* Description : ascii_to_bin_arr() - Convert ascii string to binary array
* Takes       : ascii (string) - 8-byte length ascii string
* Returns     : bin (arrayref) - 64-bit length binary array
* Notes       : Nothing
* TODO        : Nothing
**************************************************************************/
function ascii_to_bin_arr(ascii)
   {
        var n, m;
        var c;
        var row;
        
        var bin = new Array(64);
        
        
        for(n = 0; n < 8; n++)
            {
                c = ascii[n].charCodeAt();
                
                row = n*8;
                
                for(m = 0; m < 8; m++)
                    {
                        bin[row + m] = ( c >> (7-m) ) & 1;
                    }
            }

        
        return bin;
    }


/************************************************************************************
* Description : gen_round_keys(): Generate 16 48-bit round keys from one 64-bit key
* Takes       : key (arrayref) - 48 bit binary array
* Returns     : Nothing
* Sets global : K[0-15]
* Notes       : Nothing
* TODO        : Nothing
************************************************************************************/
var K = new Array(16);
for(var n = 0; n < 16; n++) { K[n] = new Array(48).fill(0); }

function gen_round_keys(key)
    {
        var n, m;
        var value;
        var offset;
        
        var parity_drop = new Array(56).fill(0);

        
        /***********************************************************************
        * Apply parity drop permutation and separate into left and right parts
        ***********************************************************************/
        for(n = 0; n < 56; n++) { parity_drop[n] = key[parity_drop_table[n]]; }
        
        
        /**********************
        * Generate round keys
        **********************/
        for(n = 0; n < 16; n++)
            {
                /****************************************************
                * Circular left shift (1, 2, 9, 16: 1; rest: 2)
                *
                * As it is very costly to shift arrays physically,
                * a logical left shift is done in it place, with an
                * offset representing the 0 index of the left and
                * right arrays.
                ****************************************************/
                offset = shift_offset[n] ;
                
                /********************************
                * Apply compression permutation
                ********************************/
                for(m = 0; m < 48; m++)
                    {
                        value = compression_table[m];
                        
                        K[n][m] = value < 28 ?
                            parity_drop[(offset + value)%28] :
                            parity_drop[(offset + value%28)%28 + 28];
                    }
            }
    }

/*******************************************************
* Description : cipher(): Cipher for the DES algorithm
* Takes       : data (arrayref) - 64 bit binary array
* Returns     : Nothing
* Sets        : data
* Notes       : Nothing
* TODO        : Nothing
*******************************************************/
function cipher(data)
    {
        var n, m;
        var k;        
        
        var temp;
        
        var value;
        var pos, row, col, dec;
        
        var L        = new Array(32).fill(0);
        var R        = new Array(32).fill(0);
        var des_R    = new Array(48).fill(0); /** Copy of R for des so that R is reusable again for swapping **/
        var S_output = new Array(32).fill(0);
        
        
        /*******************************************************************
        * Apply initial permutation and separate into left and right parts
        *******************************************************************/
        for(n = 0; n < 32; n++) { L[n]    = data[initial_table[n]]; }
        for(; n < 64; n++)      { R[n-32] = data[initial_table[n]]; }
        
        
        /*********************
        * Round 0 through 16
        *********************/
        for(n = 0; n < 16; n++)
            {
                /*************************************************************************************
                * Make a reference copy to k so that there is no need for two dimension array access
                *************************************************************************************/
                k = K[n];
                
                
                /*******************************************************************
                * Apply expansion permutation and apply xor with k
                *
                * shortcut for:
                * for(n = 0; n < 48; n++) { des_R[n]  = R[expansion_table[n]-1]; }
                * for(n = 0; n < 48; n++) { des_R[n] ^= k[n]; }
                *
                ********************************************************************/
                for(m = 0; m < 48; m++)
                    {
                        des_R[m] = k[m] ^ R[expansion_table[m]];
                    }
        
        
                /***************************
                * Apply S-Box permutations
                ***************************/
                for(m = 0; m < 8; m++)
                    {
                        /************************************************
                        * Convert from binary to decimal every six bits
                        ************************************************/
                        pos = m*6;
                        
                        row = (des_R[pos+5] << 0)
                            + (des_R[pos]   << 1);
                        
                        col = (des_R[pos+4] << 0)
                            + (des_R[pos+3] << 1)
                            + (des_R[pos+2] << 2)
                            + (des_R[pos+1] << 3);
                
                
                        /*******************************
                        * Get decimal value from s-box
                        *******************************/
                        dec = s_box_table[m][row][col];
                
                
                        /*********************
                        * Convert dec to bin
                        *********************/
                        pos = m*4;
                
                        S_output[pos]   = (dec >> 3) & 1;
                        S_output[pos+1] = (dec >> 2) & 1;
                        S_output[pos+2] = (dec >> 1) & 1;
                        S_output[pos+3] = (dec >> 0) & 1;
                    }
        
        
                /********************************************************
                * Apply straight permutation and apply xor to L with it
                *
                * shortcut for:
                * des = S_output[straight_table[n]-1];
                * for(n = 0; n < 32; n++) { L[n] ^= des[n]; }
                *
                ********************************************************/
                for(m = 0; m < 32; m++)
                    {
                        L[m] ^= S_output[straight_table[m]];
                    }
                
                
                /****************************************************
                * Swap L and R (skip last round to allow reversing)
                *****************************************************/
                if(n != 15)
                    {
                        temp = L;
                        L    = R;
                        R    = temp;
                    }
            }

        
        /*********************************************
        * Apply final permutation to data and return
        *********************************************/
        for(n = 0; n < 64; n++)
            {
                value = final_table[n];
                data[n] = value < 32 ? L[value] : R[value-32];
            }
    }


/***********************************************************************************************************
* Description : encrypt(): Encrypt input data with DES
*
* Takes       : data     (string or binary arrayref): data to be encrypted
*               key      (string or binary arrayref): key to encrypt data with
*               input_t  (string): data/key input type, can be a ascii/hex string or a binary array
*               output_t (string): digest/key output type, can be a ascii/hex/b64 string or a binary array 
*
* Returns     : digest: Encrypted data
*               key   : Encrypted key so that it can be used for decrypt
*
* Notes       : Data and key have to be of the same input type
* TODO        : Nothing
***********************************************************************************************************/
function encrypt(data, key, input_t, output_t)
    {
        /*************************************************
        * Convert input, don't do nothing if it's binary
        *************************************************/
        if( !input_t.match(/bin|ascii|hex/) )
            {
                throw 'Invalid input type: '+input_t+'.';
            }
            
        if(input_t == 'ascii')
            {
                data = ascii_to_bin_arr(data);
                key  = ascii_to_bin_arr(key);
            }
        else if(input_t == 'hex')
            {
                data = hex_to_bin_arr(data);
                key  = hex_to_bin_arr(key);
            }
        
        
        /**********************************
        * Generate round keys and encrypt
        **********************************/
        gen_round_keys(key);
        
        cipher(data);
        
        
        /*****************
        * Convert output
        *****************/
        var digest = output_t == 'bin'   ? data                         :
                     output_t == 'ascii' ? bin_arr_to_ascii(data)       :
                     output_t == 'b64'   ? btoa(bin_arr_to_ascii(data)) :
                     output_t == 'hex'   ? bin_arr_to_hex(data)         :
                                           false;

        return digest;
    }


/********************************************************************************************************
* Description : encrypt(): Decrypt input data with DES
*
* Takes       : data     (string or binary arrayref): data to be decrypted
*               key      (string or binary arrayref): key to decrypt data with
*               input_t  (string): data/key input type, can be a ascii/hex/b64 string or a binary array
*               output_t (string): digest/key output type, can be a ascii/hex string or a binary array
*
* Returns     : plaintext: Decrypted data
*               key      : Decrypted key
*
* Notes       : Data and key have to be of the same input type
* TODO        : Nothing
********************************************************************************************************/
function decrypt(data, key, input_t, output_t)
    {
        /*************************************************
        * Convert input, don't do nothing if it's binary
        *************************************************/
        if( !input_t.match(/bin|hex|ascii|b64/) )
            {
                throw 'Invalid input type: '+input_t+'.';
            }
        
        if(input_t == 'hex')
            {
                data = hex_to_bin_arr(data);
                key  = hex_to_bin_arr(key);
            }
        else if(input_t == 'ascii')
            {
                data = ascii_to_bin_arr(data);
                key  = ascii_to_bin_arr(key);
            }
        else if(input_t == 'b64')
            {
                data = ascii_to_bin_arr(atob(data));
                key  = ascii_to_bin_arr(atob(key));
            }
        
        
        /******************************************
        * Generate inverse round keys and decrypt
        ******************************************/
        gen_round_keys(key);
        K.reverse();
        
        cipher(data);
        
        
        /*****************
        * Convert output
        *****************/
        var plaintext = output_t == 'bin'   ? data                   :
                        output_t == 'ascii' ? bin_arr_to_ascii(data) :
                        output_t == 'hex'   ? bin_arr_to_hex(data)   :
                                              false;

        
        return plaintext;
    }

/*
function triple_DES(data, key1, key2, key3, input_t, output_t, mode)
    {
        var first, second, output;
        
        if(mode == 'encrypt')
            {
                first  = encrypt(data, key1, input_t);
                second = decrypt(data, key2, input_t);
                output = encrypt(data, key3, output_t);
            }
        else if(mode == 'decrypt')
            {
                first  = decrypt(data, key3, input_t);
                second = encrypt(data, key2, input_t);
                output = decrypt(data, key1, output_t);
            }

        return output;
    }
*/

//var test = triple_DES('abcdefgh', 'aaaaaaaa', 'bbbbbbbb', 'cccccccc', 'ascii', 'hex', 'encrypt');
//console.log(test);