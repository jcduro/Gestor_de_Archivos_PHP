<?php
/*

------------------------------------------------------------------------------------------------

      _  _____ _____  _    _ _____   ____  
     | |/ ____|  __ \| |  | |  __ \ / __ \ 
     | | |    | |  | | |  | | |__) | |  | |
 _   | | |    | |  | | |  | |  _  /| |  | |
| |__| | |____| |__| | |__| | | \ \| |__| |
 \____/ \_____|_____/ \____/|_|  \_\\____/ 
                                           
                                           

------------------------------------------------------------------------------------------------
*/ ?>
<?php

// Disable error reporting for undefined superglobals
error_reporting( error_reporting() & ~E_NOTICE );

// Security Options
$allow_delete = false; // Set to false to disable the Delete button and delete POST request.
$allow_upload = true; // Set to true to allow file uploads
$allow_create_folder = true; // Set to false to disable folder creation
$allow_direct_link = true; // Set to false to allow only downloads, not direct links
$allow_show_folders = true; // Set to false to hide all subdirectories

$disallowed_extensions = ['php'];  // must be an array. Extensions not allowed for upload
$hidden_extensions = ['php']; // must be an array of lowercase file extensions. Extensions hidden in the directory index

$PASSWORD = '';  // Set the password to access the file manager ... (optional)

if($PASSWORD) {
    session_start();
    if(!$_SESSION['_sfm_allowed']) {
        // sha1, and random bytes to frustrate timing attacks. Not meant as secure hashing.
        $t = bin2hex(openssl_random_pseudo_bytes(10));
        if($_POST['p'] && sha1($t.$_POST['p']) === sha1($t.$PASSWORD)) {
            $_SESSION['_sfm_allowed'] = true;
            header('Location: ?');
        }
        echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p autofocus/></form></body></html>';
        exit;
    }
}

// must be in UTF-8 or `basename` won't work
setlocale(LC_ALL,'en_US.UTF-8');

$tmp_dir = dirname($_SERVER['SCRIPT_FILENAME']);
if(DIRECTORY_SEPARATOR==='\\') $tmp_dir = str_replace('/',DIRECTORY_SEPARATOR,$tmp_dir);
$file_request = isset($_REQUEST['file']) ? $_REQUEST['file'] : '';
$tmp = get_absolute_path($tmp_dir . '/' . $file_request);

if($tmp === false)
    err(404,'File or Folder not found');
if(substr($tmp, 0,strlen($tmp_dir)) !== $tmp_dir)
    err(403,"Forbidden");
if(isset($_REQUEST['file']) && strpos($_REQUEST['file'], DIRECTORY_SEPARATOR) === 0)
    err(403,"Forbidden");

if(!$_COOKIE['_sfm_xsrf'])
    setcookie('_sfm_xsrf',bin2hex(openssl_random_pseudo_bytes(16)));
if($_POST) {
    if($_COOKIE['_sfm_xsrf'] !== $_POST['xsrf'] || !$_POST['xsrf'])
        err(403,"XSRF Failure");
}

// Al principio de tu archivo index.php, antes de cualquier HTML:
if (isset($_GET['showfile'])) {
    $file = $_GET['showfile'];
    $file = str_replace('..', '', $file); // Seguridad básica
    if (file_exists($file)) {
        $mime = mime_content_type($file);
        header("Content-Type: $mime");
        readfile($file);
        exit;
    } else {
        http_response_code(404);
        echo "File not found";
        exit;
    }
}

$file = isset($_REQUEST['file']) && $_REQUEST['file'] ? $_REQUEST['file'] : '.';
if(isset($_GET['do']) && $_GET['do'] == 'list') {
    if (is_dir($file)) {
        $directory = $file;
        $result = [];
        $files = array_diff(scandir($directory), ['.','..']);
        foreach ($files as $entry) if (!is_entry_ignored($entry, $allow_show_folders, $hidden_extensions)) {
        $i = $directory . '/' . $entry;
        $stat = stat($i);
            $result[] = [
            	'mtime' => $stat['mtime'],
            	'size' => $stat['size'],
            	'name' => basename($i),
            	'path' => preg_replace('@^\./@', '', $i),
            	'is_dir' => is_dir($i),
            	'is_deleteable' => $allow_delete && ((!is_dir($i) && is_writable($directory)) ||
                                                           (is_dir($i) && is_writable($directory) && is_recursively_deleteable($i))),
            	'is_readable' => is_readable($i),
            	'is_writable' => is_writable($i),
            	'is_executable' => is_executable($i),
            ];
        }
    } else {
        err(412,"Not a Directory");
    }
    echo json_encode(['success' => true, 'is_writable' => is_writable($file), 'results' =>$result]);
    exit;
} elseif (isset($_POST['do']) && $_POST['do'] == 'delete') {
    if($allow_delete) {
        rmrf($file);
    }
    exit;
} elseif (isset($_POST['do']) && $_POST['do'] == 'mkdir' && $allow_create_folder) {
    // do not allow actions outside the root. Also filter slashes to catch arguments like './../outside'
    $dir = $_POST['name'];
    $dir = str_replace('/', '', $dir);
    if(substr($dir, 0, 2) === '..')
        exit;
    chdir($file);
    @mkdir($_POST['name']);
    exit;
} elseif (isset($_POST['do']) && $_POST['do'] == 'upload' && $allow_upload) {
    foreach($disallowed_extensions as $ext)
        if(preg_match(sprintf('/\.%s$/',preg_quote($ext)), $_FILES['file_data']['name']))
            err(403,"Files of this type are not allowed.");

    $res = move_uploaded_file($_FILES['file_data']['tmp_name'], $file.'/'.$_FILES['file_data']['name']);
    exit;
} elseif (isset($_GET['do']) && $_GET['do'] == 'download') { 
    $filename = basename($file);
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    header('Content-Type: ' . finfo_file($finfo, $file));
    header('Content-Length: '. filesize($file));
    header(sprintf('Content-Disposition: attachment; filename=%s',
        strpos('MSIE',$_SERVER['HTTP_REFERER']) ? rawurlencode($filename) : "\"$filename\"" ));
    ob_flush();
    readfile($file);
    exit;
}

function is_entry_ignored($entry, $allow_show_folders, $hidden_extensions) {
    if ($entry === basename(__FILE__)) {
        return true;
    }

    if (is_dir($entry) && !$allow_show_folders) {
        return true;
    }

    $ext = strtolower(pathinfo($entry, PATHINFO_EXTENSION));
    if (in_array($ext, $hidden_extensions)) {
        return true;
    }

    return false;
}

function rmrf($dir) {
    if(is_dir($dir)) {
        $files = array_diff(scandir($dir), ['.','..']);
        foreach ($files as $file)
            rmrf("$dir/$file");
        rmdir($dir);
    } else {
        unlink($dir);
    }
}
function is_recursively_deleteable($d) {
    $stack = [$d];
    while($dir = array_pop($stack)) {
        if(!is_readable($dir) || !is_writable($dir))
            return false;
        $files = array_diff(scandir($dir), ['.','..']);
        foreach($files as $file) if(is_dir($file)) {
            $stack[] = "$dir/$file";
        }
    }
    return true;
}

// from: http://php.net/manual/en/function.realpath.php#84012
function get_absolute_path($path) {
        $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
        $parts = explode(DIRECTORY_SEPARATOR, $path);
        $absolutes = [];
        foreach ($parts as $part) {
            if ('.' == $part) continue;
            if ('..' == $part) {
                array_pop($absolutes);
            } else {
                $absolutes[] = $part;
            }
        }
        return implode(DIRECTORY_SEPARATOR, $absolutes);
    }

function err($code,$msg) {
    http_response_code($code);
    echo json_encode(['error' => ['code'=>intval($code), 'msg' => $msg]]);
    exit;
}

function asBytes($ini_v) {
    $ini_v = trim($ini_v);
    $s = ['g'=> 1<<30, 'm' => 1<<20, 'k' => 1<<10];
    return intval($ini_v) * ($s[strtolower(substr($ini_v,-1))] ?: 1);
}
$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));
?>
<!DOCTYPE html>
<html><head>
<meta http-equiv="content-type" content="text/html; charset=utf-8">

<style>



body {font-family: "lucida grande","Segoe UI",Arial, sans-serif;
    font-size: 14px;
    width: 1024;
    padding: 1em;
    margin: 0;
    color: #FFE; /* Cal Poly Green */
    background-image: url(final.png);
    background-repeat: no-repeat;
    background-attachment: fixed;
    background-size: cover;
    background-color: #26422A;
    margin: 40px 20px 40px 20px;
    z-index: -1;
}


th {font-weight: normal;
    color: #FFE EBC; /* Vanilla */
    background-color: #5D372A; /* Bistre */
    padding: .5em 1em .5em .2em;
    text-align: left;
    cursor: pointer;
    user-select: none;}

th .indicator {margin-left: 6px }
td {background-color: rgba(210, 232, 255, 0.4); /* Columbia Blue translúcido */
    color: #26422A; /* Cal Poly Green */ }
td a, td a:visited {
    color: inherit !important;
    text-decoration: none;
    text-transform: uppercase;
    letter-spacing: 2px;
    font-weight: bold;
}

td a.name {

    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAABAklEQVRIie2UMW6DMBSG/4cYkJClIhauwMgx8CnSC9EjJKcwd2HGYmAwEoMREtClEJxYakmcoWq/yX623veebZmWZcFKWZbXyTHeOeeXfWDN69/uzPP8x1mVUmiaBlLKsxACAC6cc2OPd7zYK1EUYRgGZFkG3/fPAE5fIjcCAJimCXEcGxKnAiICERkSIcQmeVoQhiHatoWUEkopJEkCAB/r+t0lHyVN023c9z201qiq6s2ZYA9jDIwx1HW9xZ4+Ihta69cK9vwLvsX6ivYf4FGIyJj/rg5uqwccd2Ar7OUdOL/kPyKY5/mhZJ53/2asgiAIHhLYMARd16EoCozj6EzwCYrrX5dC9FQIAAAAAElFTkSuQmCC) no-repeat 0px 12px;
    padding: 15px 5px 5px 35px;
}

td a.name:hover {
    color: #FFE EBC;
    border-radius: 3px;
    box-shadow: 0 0 8px #EA672D; /* Flame */
    background-color: rgba(234, 103, 45, 0.7);
    padding: 15px 5px 5px 35px;
}



td a.download {
    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2klEQVR4nJ2ST2sTQRiHn5mdmj92t9XmUJIWJGq9NHrRgxQiCtqbl97FqxgaL34CP0FD8Qv07EHEU0Ew6EXEk6ci8Q9JtcXEkHR3k+zujIdUqMkmiANzmJdnHn7vzCuIWbe291tSkvhz1pr+q1L2bBwrRgvFrcZKKinfP9zI2EoKmm7Azstf3V7fXK2Wc3ujvIqzAhglwRJoS2ImQZMEBjgyoDS4hv8QGHA1WICvp9yelsA7ITBTIkwWhGBZ0Iv+MUF+c/cB8PTHt08snb+AGAACZDj8qIN6bSe/uWsBb2qV24/GBLn8yl0plY9AJ9NKeL5ICyEIQkkiZenF5XwBDAZzWItLIIR6LGfk26VVxzltJ2gFw2a0FmQLZ+bcbo/DPbcd+PrDyRb+GqRipbGlZtX92UvzjmUpEGC0JgpC3M9dL+qGz16XsvcmCgCK2/vPtTNzJ1x2kkZIRBSivh8Z2Q4+VkvZy6O8HHvWyGyITvA1qndNpxfguQNkc2CIzM0xNk5QLedCEZm1VKsf2XrAXMNrA2vVcq4ZJ4DhvCSAeSALXASuLBTW129U6oPrT969AK4Bq0AeWARs4BRgieMUEkgDmeO9ANipzDnH//nFB0KgAxwATaAFeID5DQNatLGdaXOWAAAAAElFTkSuQmCC) no-repeat 0px 5px;
    padding: 4px 0 4px 20px;
}
td a.download:hover {
    color: #FFE EBC;
    border-radius: 3px;
    box-shadow: 0 0 8px #EA672D;
    background-color: rgba(234, 103, 45, 0.7);
    padding: 4px 0 4px 20px;
}


thead { border-top: 1px solid #D2E8FF;
    border-bottom: 1px solid #D2E8FF;
    border-left: 1px solid #D2E8FF;
    border-right: 1px solid #D2E8FF; }
    
    
    /* 📱 --- RESPONSIVE: Convertir tabla en tarjetas --- */
@media (max-width: 768px) {
  table, thead, tbody, th, td, tr {
    display: block;
  }

  thead {
    display: none; /* Oculta los encabezados */
  }

  tr {
    background-color: rgba(210, 232, 255, 0.3);
    border: 1px solid #D2E8FF;
    margin-bottom: 15px;
    border-radius: 8px;
    padding: 10px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.1);
  }

  td {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border: none;
    background: transparent;
  }

  td::before {
    content: attr(data-label); /* Muestra el nombre de la columna */
    font-weight: bold;
    color: #5D372A;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-right: 10px;
    flex-shrink: 0;
  }

  td a.name {
    background-position: 0px 8px;
    padding-left: 25px;
  }
}

    
#top {
  /* Columbia Blue */
  padding: 8px 20px;
  border-top-left-radius: 15px;
  border-top-right-radius: 15px;
}

/* FLEX para formularios */
#top .top-flex {
  display: flex;
  justify-content: flex-end;   /* empuja todo a la derecha */
  align-items: flex-start;
  gap: 15px;
  flex-wrap: wrap;
  padding-right: 60px;
}

#mkdir {
     border: 2px solid #26422A;
    border-radius: 12px;
    padding: 18px 20px 12px 20px;
    margin-bottom: 18px;
    display: flex;
  gap: 8px;
  align-items: center;
  transform: scale(0.9); /* un poco más compacto */
    box-shadow: 0 2px 8px rgba(31,117,204,0.07);
    max-width: 420px;
}

#mkdir label {
    font-size: 14px;
  color: #26422A; /* Cal Poly Green */
  font-weight: 600;
}

#mkdir input[type="text"] {
    width: 200px;
  border: 1px solid #B0CDEB;
  border-radius: 6px;
  background-color: #fff;
  font-size: 14px;
}

#mkdir input[type="text"]:focus {
    border-color: #EA672D;
}

#mkdir input[type="submit"] {
    background-color: #EA672D; /* Flame */
  color: #fff;
  font-weight: bold;
  border: none;
  padding: 7px 14px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.2s;
}

#mkdir input[type="submit"]:hover {
    background: linear-gradient(90deg, #5D372A 60%, #EA672D 100%);
    transform: translateY(-2px) scale(1.03);
}
label { display:block; font-size:11px; color:#555;}
#file_drop_target {
    width: 500px;      /* ajusta para encajar mejor en el rectángulo */
  max-width: 100%;
  box-sizing: border-box;
  margin-top: 5px;
     border: 2px dashed #EA672D;
  padding: 15px;
  border-radius: 10px;
  text-align: center;
  color: #26422A;
  font-size: 14px;
    box-shadow: 0 4px 16px rgba(31,117,204,0.07);
}

#file_drop_target:hover {
  background-color: #fff;
}

#file_drop_target.drag_over {
    border-color: #EA672D;
    background: #D2E8FF;
    color: #5D372A;
}
#upload_progress {padding: 4px 0;}
#upload_progress .error {color:#a00;}
#upload_progress > div { padding:3px 0;}
#upload_progress, #table {
    margin-top: 12px;
}	
.no_write #mkdir, .no_write #file_drop_target {display: none}
.progress_track {display:inline-block;width:200px;height:10px;border:1px solid #333;margin: 0 4px 0 10px;}
.progress {background-color: #82CFFA;height:10px; }
footer {font-size:11px; color:#bbbbc5; padding:4em 0 0;text-align: left;}
footer a, footer a:visited {color:#bbbbc5;}
#breadcrumb { padding-top:34px; font-size:15px; color:#aaa;display:inline-block;float:left;}
#folder_actions {width: 50%;float:right;}
a, a:visited { color:#00c; text-decoration: none}
a:hover {text-decoration: underline}
.sort_hide{ display:none;}
table {border-collapse: collapse;width:100%;}
thead {max-width: 1024px}
td { padding:.2em 1em .2em .2em; border-bottom:1px solid #def;height:30px; font-size:12px;white-space: nowrap;}
td.first {font-size:14px;white-space: normal;}
td.empty { color:#777; font-style: italic; text-align: center;padding:3em 0;}
.is_dir .size {color:transparent;font-size:0;}
.is_dir .size:before {content: "--"; font-size:14px;color:#333;}
.is_dir .download{visibility: hidden}
a.delete {display:inline-block;
    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAADtSURBVHjajFC7DkFREJy9iXg0t+EHRKJDJSqRuIVaJT7AF+jR+xuNRiJyS8WlRaHWeOU+kBy7eyKhs8lkJrOzZ3OWzMAD15gxYhB+yzAm0ndez+eYMYLngdkIf2vpSYbCfsNkOx07n8kgWa1UpptNII5VR/M56Nyt6Qq33bbhQsHy6aR0WSyEyEmiCG6vR2ffB65X4HCwYC2e9CTjJGGok4/7Hcjl+ImLBWv1uCRDu3peV5eGQ2C5/P1zq4X9dGpXP+LYhmYz4HbDMQgUosWTnmQoKKf0htVKBZvtFsx6S9bm48ktaV3EXwd/CzAAVjt+gHT5me0AAAAASUVORK5CYII=) no-repeat scroll 0 2px;
    color:#d00;	margin-left: 15px;font-size:11px;padding:0 0 0 13px;
}
.is_dir .name {
    background: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAADdgAAA3YBfdWCzAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAI0SURBVFiF7Vctb1RRED1nZu5977VQVBEQBKZ1GCDBEwy+ISgCBsMPwOH4CUXgsKQOAxq5CaKChEBqShNK222327f79n0MgpRQ2qC2twKOGjE352TO3Jl76e44S8iZsgOww+Dhi/V3nePOsQRFv679/qsnV96ehgAeWvBged3vXi+OJewMW/Q+T8YCLr18fPnNqQq4fS0/MWlQdviwVqNpp9Mvs7l8Wn50aRH4zQIAqOruxANZAG4thKmQA8D7j5OFw/iIgLXvo6mR/B36K+LNp71vVd1cTMR8BFmwTesc88/uLQ5FKO4+k4aarbuPnq98mbdo2q70hmU0VREkEeCOtqrbMprmFqM1psoYAsg0U9EBtB0YozUWzWpVZQgBxMm3YPoCiLpxRrPaYrBKRSUL5qn2AgFU0koMVlkMOo6G2SIymQCAGE/AGHRsWbCRKc8VmaBN4wBIwkZkFmxkWZDSFCwyommZSABgCmZBSsuiHahA8kA2iZYzSapAsmgHlgfdVyGLTFg3iZqQhAqZB923GGUgQhYRVElmAUXIGGVgedQ9AJJnAkqyClCEkkfdM1Pt13VHdxDpnof0jgxB+mYqO5PaCSDRIAbgDgdpKjtmwm13irsnq4ATdKeYcNvUZAt0dg5NVwEQFKrJlpn45lwh/LpbWdela4K5QsXEN61tytWr81l5YSY/n4wdQH84qjd2J6vEz+W0BOAGgLlE/AMAPQCv6e4gmWYC/QF3d/7zf8P/An4AWL/T1+B2nyIAAAAASUVORK5CYII=) no-repeat scroll 0px 10px;
    padding:15px 0 10px 40px;
}

.upload-btn {
    display: inline-block;
    margin-top: 16px;
    padding: 12px 32px;
    background: #EA672D;
    color: #FFE;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
    box-shadow: 0 2px 8px rgba(31,117,204,0.10);
    transition: background 0.2s, transform 0.2s;
    position: relative;
    overflow: hidden;
}
.upload-btn:hover {
    background: linear-gradient(90deg, #5D372A 60%, #EA672D 100%);
    transform: translateY(-2px) scale(1.03);
}
.upload-btn input[type="file"] {
    display: none;
}


#breadcrumb a {
     position: relative;
  top: -15px; /* súbelo (puedes ajustar este valor) */
  margin-bottom: 0;    
  display: inline-block;
  background-color: #EA672D; /* Flame */
  color: #fff;
  font-weight: bold;
  padding: 6px 14px;
  border-radius: 8px;
  text-decoration: none;
  margin-top: 10px;
  transition: background 0.2s;
}

#breadcrumb a:hover {
  background-color: #c8501d;
}


.top-flex {
    display: flex;
    justify-content: center;
    align-items: flex-start;
    gap: 32px;
    flex-wrap: wrap;
    width: 100%;
    margin-bottom: 12px;
}
#mkdir, #file_drop_target {
    margin: 0;
}
#imgModal {
    display: none;
    position: fixed;
    z-index: 9999;
    top: 0; left: 0;
    width: 100vw; height: 100vh;
    background: rgba(0,0,0,0.85);
    justify-content: center;
    align-items: center;
    /* Lo importante: */
    display: flex;
}



</style>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
<script>
(function($){
    $.fn.tablesorter = function() {
        var $table = this;
        this.find('th').click(function() {
            var idx = $(this).index();
            var direction = $(this).hasClass('sort_asc');
            $table.tablesortby(idx,direction);
        });
        return this;
    };
    $.fn.tablesortby = function(idx,direction) {
        var $rows = this.find('tbody tr');
        function elementToVal(a) {
            var $a_elem = $(a).find('td:nth-child('+(idx+1)+')');
            var a_val = $a_elem.attr('data-sort') || $a_elem.text();
            return (a_val == parseInt(a_val) ? parseInt(a_val) : a_val);
        }
        $rows.sort(function(a,b){
            var a_val = elementToVal(a), b_val = elementToVal(b);
            return (a_val > b_val ? 1 : (a_val == b_val ? 0 : -1)) * (direction ? 1 : -1);
        })
        this.find('th').removeClass('sort_asc sort_desc');
        $(this).find('thead th:nth-child('+(idx+1)+')').addClass(direction ? 'sort_desc' : 'sort_asc');
        for(var i =0;i<$rows.length;i++)
            this.append($rows[i]);
        this.settablesortmarkers();
        return this;
    }
    $.fn.retablesort = function() {
        var $e = this.find('thead th.sort_asc, thead th.sort_desc');
        if($e.length)
            this.tablesortby($e.index(), $e.hasClass('sort_desc') );

        return this;
    }
    $.fn.settablesortmarkers = function() {
        this.find('thead th span.indicator').remove();
        this.find('thead th.sort_asc').append('<span class="indicator">&darr;<span>');
        this.find('thead th.sort_desc').append('<span class="indicator">&uarr;<span>');
        return this;
    }
})(jQuery);
$(function(){
    var XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||0)[2];
    var MAX_UPLOAD_SIZE = <?php echo $MAX_UPLOAD_SIZE ?>;
    var $tbody = $('#list');
    $(window).on('hashchange',list).trigger('hashchange');
    $('#table').tablesorter();

    $('#table').on('click','.delete',function(data) {
        $.post("",{'do':'delete',file:$(this).attr('data-file'),xsrf:XSRF},function(response){
            list();
        },'json');
        return false;
    });

    $('#mkdir').submit(function(e) {
        var hashval = decodeURIComponent(window.location.hash.substr(1)),
            $dir = $(this).find('[name=name]');
        e.preventDefault();
        $dir.val().length && $.post('?',{'do':'mkdir',name:$dir.val(),xsrf:XSRF,file:hashval},function(data){
            list();
        },'json');
        $dir.val('');
        return false;
    });
<?php if($allow_upload): ?>
    // file upload stuff
    $('#file_drop_target').on('dragover',function(){
        $(this).addClass('drag_over');
        return false;
    }).on('dragend',function(){
        $(this).removeClass('drag_over');
        return false;
    }).on('drop',function(e){
        e.preventDefault();
        var files = e.originalEvent.dataTransfer.files;
        $.each(files,function(k,file) {
            uploadFile(file);
        });
        $(this).removeClass('drag_over');
    });
    $('input[type=file]').change(function(e) {
        e.preventDefault();
        $.each(this.files,function(k,file) {
            uploadFile(file);
        });
    });


	  // --- Carrusel de imágenes ---
    let imageFiles = [];
    let currentImgIdx = 0;

    // Detecta si es imagen por extensión
    function isImage(filename) {
        return /\.(jpe?g|png|gif|bmp|webp)$/i.test(filename);
    }

   

    // Cuando se actualiza la lista, guarda las imágenes
    function updateImageList() {
        imageFiles = [];
        $('#list tr').each(function(){
            var $a = $(this).find('a.img-link');
            if ($a.length) {
                imageFiles.push($a.attr('href'));
            }
        });
    }

    // Abre el modal al hacer click en imagen
    $(document).on('click', 'a.img-link', function(e){
        e.preventDefault();
        updateImageList();
        let imgHref = $(this).attr('href');
        currentImgIdx = imageFiles.indexOf(imgHref);
        showModalImg(currentImgIdx);
    });

    function showModalImg(idx) {
        if (idx < 0 || idx >= imageFiles.length) return;
        $('#modalImg').attr('src', imageFiles[idx]);
        $('#imgModal').fadeIn(150);
    }

    $('#closeModal').click(function(){
        $('#imgModal').fadeOut(150);
    });
    $('#prevImg').click(function(){
        if (currentImgIdx > 0) {
            currentImgIdx--;
            showModalImg(currentImgIdx);
        }
    });
    $('#nextImg').click(function(){
        if (currentImgIdx < imageFiles.length - 1) {
            currentImgIdx++;
            showModalImg(currentImgIdx);
        }
    });

    // Cierra modal con fondo
    $('#imgModal').click(function(e){
        if (e.target === this) $(this).fadeOut(150);
    });

    // Actualiza lista de imágenes cada vez que se lista la carpeta
    $(window).on('hashchange', function(){ setTimeout(updateImageList, 300); });
    setTimeout(updateImageList, 500);

    function uploadFile(file) {
        var folder = decodeURIComponent(window.location.hash.substr(1));

        if(file.size > MAX_UPLOAD_SIZE) {
            var $error_row = renderFileSizeErrorRow(file,folder);
            $('#upload_progress').append($error_row);
            window.setTimeout(function(){$error_row.fadeOut();},5000);
            return false;
        }

        var $row = renderFileUploadRow(file,folder);
        $('#upload_progress').append($row);
        var fd = new FormData();
        fd.append('file_data',file);
        fd.append('file',folder);
        fd.append('xsrf',XSRF);
        fd.append('do','upload');
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '?');
        xhr.onload = function() {
            $row.remove();
            list();
          };
        xhr.upload.onprogress = function(e){
            if(e.lengthComputable) {
                $row.find('.progress').css('width',(e.loaded/e.total*100 | 0)+'%' );
            }
        };
        xhr.send(fd);
    }
    function renderFileUploadRow(file,folder) {
        return $row = $('<div/>')
            .append( $('<span class="fileuploadname" />').text( (folder ? folder+'/':'')+file.name))
            .append( $('<div class="progress_track"><div class="progress"></div></div>')  )
            .append( $('<span class="size" />').text(formatFileSize(file.size)) )
    };
    function renderFileSizeErrorRow(file,folder) {
        return $row = $('<div class="error" />')
            .append( $('<span class="fileuploadname" />').text( 'Error: ' + (folder ? folder+'/':'')+file.name))
            .append( $('<span/>').html(' file size - <b>' + formatFileSize(file.size) + '</b>'
                +' exceeds max upload size of <b>' + formatFileSize(MAX_UPLOAD_SIZE) + '</b>')  );
    }
<?php endif; ?>
    function list() {
        var hashval = window.location.hash.substr(1);
        $.get('?do=list&file='+ hashval,function(data) {
            $tbody.empty();
            $('#breadcrumb').empty().html(renderBreadcrumbs(hashval));
            if(data.success) {
                $.each(data.results,function(k,v){
                    $tbody.append(renderFileRow(v));
                });
                !data.results.length && $tbody.append('<tr><td class="empty" colspan=5>This folder is empty</td></tr>')
                data.is_writable ? $('body').removeClass('no_write') : $('body').addClass('no_write');
            } else {
                console.warn(data.error.msg);
            }
            $('#table').retablesort();
        },'json');
    }
function renderFileRow(data) {
    // Detecta si es imagen
    function isImage(filename) {
        return /\.(jpe?g|png|gif|bmp|webp)$/i.test(filename);
    }
    var $link = $('<a class="name" />')
        .attr('href', data.is_dir ? '#' + encodeURIComponent(data.path) : '?showfile=' + encodeURIComponent(data.path))
        .attr('target', data.is_dir ? '' : '_blank')
        .text(data.name);

    // Si es imagen, agrega la clase img-link
    if (!data.is_dir && isImage(data.name)) {
        $link.addClass('img-link');
    }
    // ...resto igual...
        var allow_direct_link = <?php echo $allow_direct_link?'true':'false'; ?>;
            if (!data.is_dir && !allow_direct_link)  $link.css('pointer-events','none');
        var $dl_link = $('<a/>').attr('href','?do=download&file='+ encodeURIComponent(data.path))
            .addClass('download').text('download');
        var $delete_link = $('<a href="#" />').attr('data-file',data.path).addClass('delete').text('delete');
        var perms = [];
        if(data.is_readable) perms.push('read');
        if(data.is_writable) perms.push('write');
        if(data.is_executable) perms.push('exec');
        var $html = $('<tr />')
            .addClass(data.is_dir ? 'is_dir' : '')
            .append( $('<td class="first" />').append($link) )
            .append( $('<td/>').attr('data-sort',data.is_dir ? -1 : data.size)
                .html($('<span class="size" />').text(formatFileSize(data.size))) )
            .append( $('<td/>').attr('data-sort',data.mtime).text(formatTimestamp(data.mtime)) )
            .append( $('<td/>').text(perms.join('+')) )
            .append( $('<td/>').append($dl_link).append( data.is_deleteable ? $delete_link : '') )
        return $html;
    }
    function renderBreadcrumbs(path) {
        var base = "",
            $html = $('<div/>').append( $('<a href=#>Home</a></div>') );
        $.each(path.split('%2F'),function(k,v){
            if(v) {
                var v_as_text = decodeURIComponent(v);
                $html.append( $('<span/>').text(' ▸ ') )
                    .append( $('<a/>').attr('href','#'+base+v).text(v_as_text) );
                base += v + '%2F';
            }
        });
        return $html;
    }
    function formatTimestamp(unix_timestamp) {
        var m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        var d = new Date(unix_timestamp*1000);
        return [m[d.getMonth()],' ',d.getDate(),', ',d.getFullYear()," ",
            (d.getHours() % 12 || 12),":",(d.getMinutes() < 10 ? '0' : '')+d.getMinutes(),
            " ",d.getHours() >= 12 ? 'PM' : 'AM'].join('');
    }
    function formatFileSize(bytes) {
        var s = ['bytes', 'KB','MB','GB','TB','PB','EB'];
        for(var pos = 0;bytes >= 1000; pos++,bytes /= 1024);
        var d = Math.round(bytes*10);
        return pos ? [parseInt(d/10),".",d%10," ",s[pos]].join('') : bytes + ' bytes';
    }
})



</script>
</head>
<body>
<div id="top">
  <div class="top-flex">
    <?php if($allow_create_folder): ?>
      <form action="?" method="post" id="mkdir">
        <label for=dirname>Create New Folder</label>
        <input id=dirname type=text name=name value="" placeholder="Folder name" />
        <input type="submit" value="Create" />
      </form>
    <?php endif; ?>

    <?php if($allow_upload): ?>
      <div id="file_drop_target">
        Drag files here to upload
        <br><b>or</b><br>
        <label class="upload-btn">
          Choose files
          <input type="file" multiple style="display:none;" />
        </label>
      </div>
    <?php endif; ?>
  </div>
  <div id="breadcrumb">&nbsp;</div>
</div>

<div id="upload_progress"></div>
<table id="table"><thead><tr>
    <th>Name</th>
    <th>Size</th>
    <th>Modified</th>
    <th>Permissions</th>
    <th>Actions</th>
</tr></thead><tbody id="list">

</tbody></table>
<footer>File Manager <a href="index.php">Jcduro's Page</a></footer>


<!-- Carrusel Modal -->

<div id="imgModal" style="display:none;">
  <span id="closeModal" style="position:absolute;top:24px;right:40px;font-size:40px;color:#fff;cursor:pointer;">&times;</span>
  <button id="prevImg" style="position:absolute;left:30px;top:50%;transform:translateY(-50%);font-size:40px;color:#fff;background:none;border:none;cursor:pointer;">&#8592;</button>
  <img id="modalImg" src="" style="max-width:80vw;max-height:80vh;border-radius:12px;box-shadow:0 0 24px #000;">
  <button id="nextImg" style="position:absolute;right:30px;top:50%;transform:translateY(-50%);font-size:40px;color:#fff;background:none;border:none;cursor:pointer;">&#8594;</button>
</div>

</body>
</html>

