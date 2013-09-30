var os = require('os');
var random = require("node-random");

var nodejs_ibekg;

if (os.arch() === "x64") {
    if (os.type() === "Windows_NT") {
        //nodejs_ibekg = require('../../../win32/nodejs_ibekg/x64/Debug/Out/nodejs_ibekg.node');
        //nodejs_ibekg = require('../../../win32/nodejs_ibekg/x64/Debug-FIPS/Out/nodejs_ibekg.node');
        nodejs_ibekg = require('../../../win32/nodejs_ibekg/x64/Release-FIPS/Out/nodejs_ibekg.node');
    } else {
        if (os.type() === "Linux") {
            nodejs_ibekg = require('../../../build/Release/nodejs_ibekg.node');
        }
    }
} else {
    if (os.type() === "Windows_NT") {
        //nodejs_ibekg = require('../../../win32/nodejs_ibekg/Debug/Out/nodejs_ibekg.node');
        //nodejs_ibekg = require('../../../win32/nodejs_ibekg/Debug-FIPS/Out/nodejs_ibekg.node');
        nodejs_ibekg = require('../../../win32/nodejs_ibekg/Release-FIPS/Out/nodejs_ibekg.node');
    } else {
        if (os.type() === "Linux") {
            nodejs_ibekg = require('../../../build/Release/nodejs_ibekg.node');
        }
    }
}

os.type()

var ibekg = new nodejs_ibekg.Ibekg();

var crypto_info_json = ibekg.getCryptoInfo();

var crypto_info_json_obj = JSON.parse(crypto_info_json);

console.log(crypto_info_json);

var ibekgURI = "https://airykey.org";

setupEngineOptions = {
    "ibekgURI": ibekgURI,
    "masterKeyStorageEntropy": "5ae440a9a4c20c4f8d2bd7557d4af67d731ffa2039fb5893d7d0eb0312a23d0c"
}

createMasterKeyOptions = {
    "currentDate": "2013-09-15" // ISO 8601 gmtime - safety rewrite
}

encryptDataKeyOptions = {
    "anonymityLevel": 0
}

decryptDataKeyOptions = {
    //
}

var senderId = 'A'; //одговарајући@gmail.com
var receiverId = 'A';
var receiverIdArr = ['foo', '(212) 664-7665', 'д', 'одговарајући@gmail.com', 'test@gmail.com'];

var dataHashArr = ['78D8ACDF067E656AC2374B0C1A457B62DC86648CCE5A74691391CA442BEC9A2A', '0DD2C1290C175AA653442D6B277CFC6DB6E998D6BDC5DFE8663DB0AA400AF9F3'];

var nonceEntropy = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263,
 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287,
 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311,
 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335,
 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359,
 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383];

if (crypto_info_json_obj.fips_build == 'true') {
    console.log('calling FIPS build');

    GetEntropy = function (entlen, callback) {
        console.log('GetEntropy called: ' + entlen);
        random.numbers({
            "number": entlen,
            //"number": 1, // Only for testing!!!
            "minimum": 0,
            "maximum": 255
        }, function (err, data) {
            if (err) {
                console.log(err);
            } else {
                callback(data);
                //callback(nonceEntropy); // Only for testing!!!
            }
        });
    }

    GetEntropy(crypto_info_json_obj.entropy_bufs_size, function (data) {
        ibekg.setupEngine(setupEngineOptions, function (entlen) {
            if (crypto_info_json_obj.entropy_bufs_size < entlen) {
                return "entropy_bufs_size < entlen";
            } else {
                return data;
            }
        });

        if (crypto_info_json_obj.masterkey_stored == 'false') {
            console.log('createMasterKey called');
            ibekg.createMasterKey(createMasterKeyOptions);
        }

        ibekg.encryptDataKey(encryptDataKeyOptions, dataHashArr, senderId, receiverIdArr, function (err, result) {
            //ibekg.encryptDataKey(encryptDataKeyOptions, dataHashArr, senderId, function (err, result) {
            if (err) {
                console.log(err);
                //throw err;
            } else {
                var identityCipherArr = [];
                //var dataCipherArr = result.dataCipherArr;
                var dataCipherArr = result;
                for (var i = 0; i < dataCipherArr.length; i++) {
                    delete dataCipherArr[i].dataKey;
                    delete dataCipherArr[i].dataIV;
                    for (var j = 0; j < dataCipherArr[i].identityCipherArr.length; j++) {
                        identityCipherArr.push(dataCipherArr[i].identityCipherArr[j]);
                    }
                }
                //console.log(JSON.stringify(identityCipherArr));
                //console.log(JSON.stringify(dataCipherArr));
                ibekg.decryptDataKey(decryptDataKeyOptions, receiverId, identityCipherArr, function (err, result) {
                    if (err) {
                        console.log(err);
                        //throw err;
                    } else {
                        //console.log(result);
                        console.log(JSON.stringify(result));
                    }
                });
                //ibekg.secureFreeMem();
                //return result;
            }
        });
    });
} else {
    console.log('calling no FIPS build');

    ibekg.setupEngine(setupEngineOptions);

    if (crypto_info_json_obj.masterkey_stored == 'false') {
        console.log('createMasterKey called');
        ibekg.createMasterKey();
    }

    ibekg.encryptDataKey(encryptDataKeyOptions, dataHashArr, senderId, receiverIdArr, function (err, result) {
        if (err) {
            console.log(err);
            //throw err;
        } else {
            var identityCipherArr = [];
            var dataCipherArr = result;
            for (var i = 0; i < dataCipherArr.length; i++) {
                delete dataCipherArr[i].dataKey;
                delete dataCipherArr[i].dataIV;
                for (var j = 0; j < dataCipherArr[i].identityCipherArr.length; j++) {
                    identityCipherArr.push(dataCipherArr[i].identityCipherArr[j]);
                }
            }
            //console.log(JSON.stringify(identityCipherArr));
            ibekg.decryptDataKey(decryptDataKeyOptions, receiverId, identityCipherArr, function (err, result) {
                if (err) {
                    console.log(err);
                    //throw err;
                } else {
                    //console.log(result);
                    console.log(JSON.stringify(result));
                }
            });
            //ibekg.secureFreeMem();
            //return result;
        }
    });
}
