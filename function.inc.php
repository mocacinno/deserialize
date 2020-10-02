<?php
function translateunlockingscript($input)
{
	$output = array();
	$output_codes = '';
	$codedb = array(0 => 'OP_FALSE', 79 => 'OP_1NEGATE', 81 => 'OP_TRUE', 97 => 'OP_NOP', 99 => 'OP_IF', 100 => 'OP_NOTIF', 103 => 'OP_ELSE', 104 => 'OP_ENDIF', 105 => 'OP_VERIFY', 106 => 'OP_RETURN', 107 => 'OP_TOALTSTACK', 108 => 'OP_FROMALTSTACK', 115 => 'OP_IFDUP', 116 => 'OP_DEPTH', 117 => 'OP_DROP', 118 => 'OP_DUP', 119 => 'OP_NIP', 120 => 'OP_OVER', 121 => 'OP_PICK', 122 => 'OP_ROLL', 123 => 'OP_ROT', 124 => 'OP_SWAP', 125 => 'OP_TUCK', 109 => 'OP_2DROP', 110 => 'OP_2DUP', 111 => 'OP_3DUP', 112 => 'OP_2OVER', 113 => 'OP_2ROT', 114 => 'OP_2SWAP', 126 => 'OP_CAT', 127 => 'OP_SUBSTR', 128 => 'OP_LEFT', 129 => 'OP_RIGHT', 130 => 'OP_SIZE', 131 => 'OP_INVERT', 132 => 'OP_AND', 133 => 'OP_OR', 134 => 'OP_XOR', 135 => 'OP_EQUAL', 136 => 'OP_EQUALVERIFY', 139 => 'OP_1ADD', 140 => 'OP_1SUB', 141 => 'OP_2MUL', 142 => 'OP_2DIV', 143 => 'OP_NEGATE', 144 => 'OP_ABS', 145 => 'OP_NOT', 146 => 'OP_0NOTEQUAL', 147 => 'OP_ADD', 148 => 'OP_SUB', 149 => 'OP_MUL', 150 => 'OP_DIV', 151 => 'OP_MOD', 152 => 'OP_LSHIFT', 153 => 'OP_RSHIFT', 154 => 'OP_BOOLAND', 155 => 'OP_BOOLOR', 156 => 'OP_NUMEQUAL', 157 => 'OP_NUMEQUALVERIFY', 158 => 'OP_NUMNOTEQUAL', 159 => 'OP_LESSTHAN', 160 => 'OP_GREATERTHAN', 161 => 'OP_LESSTHANOREQUAL', 162 => 'OP_GREATERTHANOREQUAL', 163 => 'OP_MIN', 164 => 'OP_MAX', 165 => 'OP_WITHIN', 166 => 'OP_RIPEMD160', 167 => 'OP_SHA1', 168 => 'OP_SHA256', 169 => 'OP_HASH160', 170 => 'OP_HASH256', 171 => 'OP_CODESEPARATOR', 172 => 'OP_CHECKSIG', 173 => 'OP_CHECKSIGVERIFY', 174 => 'OP_CHECKMULTISIG', 175 => 'OP_CHECKMULTISIGVERIFY', 177 => 'OP_CHECKLOCKTIMEVERIFY', 178 => 'OP_CHECKSEQUENCEVERIFY', 253 => 'OP_PUBKEYHASH', 254 => 'OP_PUBKEY', 255 => 'OP_INVALIDOPCODE', 80 => 'OP_RESERVED', 98 => 'OP_VER', 101 => 'OP_VERIF', 102 => 'OP_VERNOTIF', 137 => 'OP_RESERVED1', 138 => 'OP_RESERVED2');
	//https://en.bitcoin.it/wiki/Script
	while (strlen($input)>0)
	{
		
		list($input, $code_hex) = getnext($input, 2);
		(int)$code_dec = hexdec($code_hex);
		$output_codes .= $code_dec . '.';
		if ($code_dec >0 && $code_dec < 76)
		{
			$aantal = $code_dec * 2;

			list($input, $data) = getnext($input, $aantal);
			$output[] = '&lt;' . $data . '&gt;';
		}
		elseif ( $code_dec > 75 && $code_dec < 79)
		{
			if ($code_dec == 76)
			{
				$aantal = 2;
				$text = 'OP_PUSHDATA1 &lt;';
			}
			elseif ($code_dec == 77)
			{
				$aantal = 4;
				$text = 'OP_PUSHDATA2 &lt;';
			}
			else
			{
				$aantal = 8;
				$text = 'OP_PUSHDATA4 &lt;';
			}
			list($input, $data) = getnext($input, $aantal);
			$output[] =  $data . ' &gt;';
		}
		elseif ( $code_dec > 81 && $code_dec < 97)
		{
			$number = $code - 80;
			$output[] = 'OP_' . $number;
		}
		elseif ( $code_dec ==176)
		{
			$output[] = 'OP_NOP1';
		}
		elseif ( $code_dec > 178 && $code_dec < 186)
		{
			$number = $code_dec - 175;
			$output[] = 'OP_NOP' . $number;
		}
		else
		{
			$output[]= $codedb[$code_dec];
		}
	}
	$output = implode(' ',$output);
	return $output;
}

function getnext($input, $lenght)
{
	$output = substr($input, 0, $lenght);
	$input = substr($input, $lenght);
	return array($input,$output);
}

function reversehex($input_hex)
{
	$input_bin = hex2bin($input_hex);
	$input_bin_reversed = strrev($input_bin);
	$input_hex_reversed = bin2hex($input_bin_reversed);
	return $input_hex_reversed;
}

function deserialiseer($tx)
{
        $return = array();
        $return['rawtx'] = $tx;
		list($tx, $version_reversed_hex) = getnext($tx,8);
		$version = hexdec(reversehex($version_reversed_hex));
        $return['version'] = $version;
        $segwitflag = substr($tx,0, 4);
        
        if ($segwitflag == '0001')
        {
                $return['segwitflag'] = '0001';
                $return['segwit'] = 1;
                $tx = substr($tx,4);
				
				list($tx, $incounter) = getnext($tx,2);
                if ($incounter == 'fd')
                {
						//fe and ff omitted, tx would be > 100 kbytes
						list($tx, $incounter_2) = getnext($tx,2);
                        $nbinputs = 512 + hexdec($incounter_2);
                }
                else
                {
                        $nbinputs = hexdec($incounter);
                }
                $return['numberofinputs'] = $nbinputs;
                $inputs = array();
                $input_indexes = array();
                $input_nsequence = array();
                $input_unlockingscript = array();
                $segwitflag = array();
				list($tx, $sequence_in_witness) = getnext($tx,2);			
                for ($i=0; $i <$nbinputs; $i+=1) 
                {
						list($tx, $reversedhash_hex) = getnext($tx,64);	
						$previoustxid = reversehex($reversedhash_hex);
                        $inputs[$i] = $previoustxid;
                        
						list($tx, $input_index_reversed_hex) = getnext($tx,8);
						$input_index = hexdec(reversehex($input_index_reversed_hex));
                        $input_indexes[$i] = $input_index;
                        //extra reading
                        //https://en.bitcoinwiki.org/wiki/NSequence
                        //http://hongchao.me/anatomy-of-raw-bitcoin-transaction/
                        //https://www.reddit.com/r/Bitcoin/comments/47upgx/nsequence_and_optin_replacebyfee_difference/
						list($tx, $lengte_unlockingscript) = getnext($tx,2);  
						
						
						$lengte_unlockingscript_dec = 2* hexdec($lengte_unlockingscript);
						$unlockingscript_input = '';
						$unlockingscript = ''; 
						for ($j=0; $j <$lengte_unlockingscript_dec; $j+=1)
						{
							$unlockingscript_input.= substr($tx,0, 1);
							$tx = substr($tx,1);
						}
						
						list($tx, $sequencenumber_reversed_hex) = getnext($tx,8); 
						$sequencenumber = hexdec(reversehex($sequencenumber_reversed_hex));
						if ($sequencenumber < 4294967294)
						{
							$segwithflag[$i] = 1; 
						}
						else
						{
							$segwithflag[$i] = 0; 
						}
                        $input_unlockingscript[$i] = $unlockingscript_input;
                        $input_nsequence[$i] = $sequencenumber;       
                }
                $return['inputs'] = $inputs;
                $return['input_indexes'] = $input_indexes;
                $return['input_unlockingscript'] = $input_unlockingscript;
                $return['input_segwithflag'] = $segwithflag;
                $return['input_nsequence'] = $input_nsequence;
                
				list($tx, $outcounter) = getnext($tx,2);
                if ($outcounter == 'fd')
                {
						//fe and ff omitted, tx would be > 100 kb)
						list($tx, $outcounter_2) = getnext($tx,2);
                        $nboutputs = 512 + hexdec($outcounter_2);
                }
                else
                {
                        $nboutputs = hexdec($outcounter);
                }
                $return['numberofoutputs'] = $nboutputs;
                $output_values_sats = array();
				$output_unlockingscript = array();
				$output_unlockingscript_translated = array();
                for ($i=0; $i <$nboutputs; $i+=1)
                {
					list($tx, $reversedsat_hex) = getnext($tx,16);
					$sat_dec = hexdec(reversehex($reversedsat_hex));
					list($tx, $scriptlengt_hex) = getnext($tx,2); 
					$scriptlengt_dec = 2* hexdec($scriptlengt_hex);
					$unlockingscript_output = '';
					for ($j=0; $j <$scriptlengt_dec; $j+=1)
					{
						$unlockingscript_output.= substr($tx,0, 1);
						$tx = substr($tx,1);
					}
					$output_unlockingscript[$i] = $unlockingscript_output;
					$output_unlockingscript_translated[$i] = translateunlockingscript($unlockingscript_output);
					$output_values_sats[$i] = $sat_dec;
                }
                $return['output_unlockingscript'] =  $output_unlockingscript;
                $return['output_values_sats'] = $output_values_sats;
                $return['output_unlockingscript_translated'] = $output_unlockingscript_translated;
				$witnessdata = substr($tx,0,-8);
				$locktime_hex_reverse = substr($tx, -8);
				$locktime_dec = hexdec(reversehex($locktime_hex_reverse));
				$return['witnessdata'] = $witnessdata;
				$return['locktime'] = $locktime_dec;
        }
        else
        {
                $return['segwit'] = 0;
        }
        return $return;
        
}

function hex_tx_to_size_bytes($hex_tx)
{
        $lengte = strlen($hex_tx);
        $bytes = floor($lengte/2);
        return $bytes;
}







?>
