<?php 

if ($handle = opendir('/home/nacharov/Downloads/cdr/')) {

    while (false !== ($entry = readdir($handle))) {

        if ($entry != "." && $entry != "..") {
            $name=explode(".",$entry);
            shell_exec("java org.bouncycastle.asn1.util.StandaloneDecoder ~/Downloads/cdr/$entry > ~/Downloads/cdr/conv/$name[0].json");

        }
    }

    closedir($handle);
}


// for($i=0;$i<10;$i++){
//    shell_exec("java org.bouncycastle.asn1.util.StandaloneDecoder ~/Downloads/B2016111501744.dat >> cdri.txt");
// }

?>
