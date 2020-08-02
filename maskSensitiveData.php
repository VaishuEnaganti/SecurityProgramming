<?php
/*
* The function maskSensitiveData takes a string input and masks three
* sensitive data fields namely credit card number, credit card expiry date and
* credit card CVV value and returns the masked data string.
* It also takes an optional array of regular expression strings to mask 
* any other sensitive data fields if needed.
*
* I use regular expressions to identify the three sensitive data field names.
* I also additionally use three helper functions to ensure that I am masking 
* the true sensitive data values. These functions help reduce the potential 
* false positives that might occur when other field names match with sensitive
* data field names.
*/

// function to verify the Expirycode
function isValidExpiry($number) 
{
    $test = strval($number);
    
    # the number should contain only 4 digits
    if (strlen($test) != 4)
    {
        return false;
    }
    
    $lines = str_split($test);
    $digit0 = intval($lines[0]);
    $digit1 = intval($lines[1]);
    
    // the first two digits represent the month and can take values from 01 to 12
    return (($digit0 == 0 OR $digit0 == 1) AND
            !($digit0 == 0 AND $digit1 == 0) AND
            ($digit0 == 1 AND $digit1 < 3) );
}

// function to verify the CVV code
function isValidCVV($number)
{
    $test = strval($number);
    
    # the number should cpntain only 3 digits
    return (strlen($test) == 3);
}

// function to verify the CardNumber
function isValidCardNumber($number)
{
    $test = strval($number);
    
    # the number should cpntain digits between 13 qnd 16
    if (strlen($test) < 13 | strlen($test) > 16)
    {
        return false;
    }
    
    $lines = str_split($test);
    $len = count($lines);
    $sum1 = 0;
    $sum2 = 0;
    
    //I am using the luhn algorithm logic to test if the number is  a
    //vaild credit card number
    for ($a = $len-2; $a >= 0; $a-=2)
    {
        $d = 2 * $lines[$a];
        strval($d);
        if (strlen($d) == 2)
        {
            $v = str_split($d);
            $d = $v[0] + $v[1];
        }
        $sum1 = $sum1 + $d;
    }
    
    for ($a = $len-1; $a >= 0; $a-=2)
    {
        $sum2 = $sum2 + $lines[$a];
    }
    $sumfinal = $sum1 + $sum2;
    
    return ($sumfinal%10 === 0);
}

// The function that masks the sensitive data fields and returns the string
function maskSensitiveData($input, $otherSecureFields = [])
{
    // I assume that the demiliter that seperates various fields in the string
    // is either "\n" or ".". If the data fields are seperated by some other
    // delimiter the below code can easily be extended to take care of it.
    $afsplt = explode("\n", $input);
    if (count($afsplt) > 1 )
    {
        $a = 0;
    }
    else
    {
        $afsplt = explode(".", $input);
        $a = 1;
    }
    
    // The mainSecureFields contains the regular expression strings for the
    //three sensitive data fields.
    $mainSecureFields = ["#card_*(data)*Number#i", "#Exp[^a-z]|Expiry#i", "#CVV#i"];
    
    // The otherSecureFields are merged with the above array to form
    // allSecureFields.
    $allSecureFields = array_merge($mainSecureFields, $otherSecureFields);
    
    for ($index = 0; $index < count($afsplt); $index++)
    {
        for ($fieldNum = 0; $fieldNum < count($allSecureFields); $fieldNum++)
        {
            $ans = preg_match($allSecureFields[$fieldNum], $afsplt[$index]);
            
            if ($ans == 1)
            {
                // I serch for numerical data in the line
                preg_match_all('#\d+#', $afsplt[$index], $matches);
                
                if (count($matches[0]) > 0 )
                {
                    $thenumber = $matches[0][0];
                    
                    //If any of the validation fails we don't mask that data
                    // to avoid false positive.
                    if (($fieldNum == 0 AND !isValidCardNumber($thenumber))
                        OR ($fieldNum == 1 AND !isValidExpiry($thenumber))
                        OR ($fieldNum == 2 AND !isValidCVV($thenumber)))
                    {
                        break;
                    }
                    
                    $afsplt[$index] = str_replace($thenumber, str_repeat("*", strlen($thenumber)), $afsplt[$index]);
                }
                break;
            }
        }
    }
    
    $result = "";
    switch ($a)
    {
        case 0:
            $result = implode("\n", $afsplt);
            break;
        case 1:
        default:
            $result = implode(".", $afsplt);
    }
    
    return $result;
}

$testcase1 = 
'{"MsgTypId": 111231232300,
"CardNumber": "4242424242424242",
"CardExp": 1224,
"CardCVV": 240,
"TransProcCd": "004800",
"TransAmt": "57608",
"MerSysTraceAudNbr": "456211",
"TransTs": "180603162242",
"AcqInstCtryCd": "840",
"FuncCd": "100",
"MsgRsnCd": "1900",
"MerCtgyCd": "5013",
"AprvCdLgth": "6",
"RtrvRefNbr": "1029301923091239"
}';

$testcase2 = 
"[orderId] => 212939129
[orderNumber] => INV10001
[salesTax] => 1.00
[amount] => 21.00
[terminal] => 5
[currency] => 1
[type] => purchase
[avsStreet] => 123 Road
[avsZip] => A1A 2B2
[customerCode] => CST1001
[cardId] => 18951828182
[cardHolderName] => John Smith
[cardNumber] => 5454545454545454
[cardExpiry] => 1025
[cardCVV] => 100";

$testcase3 = 
"Request=Credit Card.Auth Only&Version=4022&HD.Network_Status_Byte=*&HD.Application_ID=TZAHSK!&HD."
. "Terminal_ID=12991kakajsjas&HD.Device_Tag=000123&07."
. "POS_Entry_Capability=1&07.PIN_Entry_Capability=0&07.CAT_Indicator=0&07."
. "Terminal_Type=4&07.Account_Entry_Mode=1&07.Partial_Auth_Indicator=0&07.Account_Card_Number="
. "4242424242424242&07.Account_Expiry=1024&07.Transaction_Amount=142931&07."
. "Association_Token_Indicator=0&17.CVV=200&17.Street_Address=123 Road SW&17.Postal_Zip_Code=90210&17.Invoice_Number=INV19291";

$testcase4 = 
"<?xml version='1.0' encoding='UTF-8'?>
<Request>
<NewOrder>
<IndustryType>MO</IndustryType>
<MessageType>AC</MessageType>
<BIN>000001</BIN>
<MerchantID>209238</MerchantID>
<TerminalID>001</TerminalID>
<CardBrand>VI</CardBrand>
<CardDataNumber>5454545454545454</CardDataNumber>
<Exp>1226</Exp>
<CVVCVCSecurity>300</CVVCVCSecurity>
<CurrencyCode>124</CurrencyCode>
<CurrencyExponent>2</CurrencyExponent>
<AVSzip>A2B3C3</AVSzip>
<AVSaddress1>2010 Road SW</AVSaddress1>
<AVScity>Calgary</AVScity>
<AVSstate>AB</AVSstate>
<AVSname>JOHN R SMITH</AVSname>
<OrderID>23123INV09123</OrderID>
<Amount>127790</Amount>
</NewOrder>
</Request>";


echo    maskSensitiveData($testcase1)."\n"."\n";
echo    maskSensitiveData($testcase2,["#OrderID#i"])."\n"."\n";
echo    maskSensitiveData($testcase3)."\n"."\n";
echo    maskSensitiveData($testcase4,["#CurrencyCode#i"]);

