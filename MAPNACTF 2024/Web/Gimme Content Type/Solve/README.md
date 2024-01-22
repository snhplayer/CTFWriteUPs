Content-Type solver

Because the challenge checks sec-fetch-mode=navigate you can't use script tags or anything else except frames and window.open(). 

Cookies are None so iframe navigations contain cookies. 
A simple solution would be using meta tags but they this doesn't work because the message contains quote and double-quotes. Using text/html and xml like content types is pretty much hopeless... the intended solution uses application/pdf.


pdfs in chrome are parsed and rendered by pdfium which is kinda like an internal extension by google.


Pdfium can handle javascript codes inside PDFs ( Dedicated js parser and renderer ) which allows you to do  some scripting despite the csp. But pdfium doesn't allow using fetch() or something like that ( It has whole different methods ).

The solution requires you to check how you can abuse js APIs to exfil a true false value to parent frame. The goal is developing a pdf files which lets the parent frame knows that 1==1 or 1==2.


For example if we consider this code: `<iframe src="http://web/?content_type=application/pdf&letter=PDFSTART if($gift$[0]==1){app.alert()} PDFEND" onblur="alert(first char of gift is 1)"></iframe>`, the onblur event of parent frame is triggered which lets you know that the first element of gift is 1. But using onblur doesn't work because it doesn't work on headless chrome and it probably only works once.

The intended solution abuses the fact that using app.alert() closes the previously opened alert()... opening alert() stops the js renderer until the tab receives an OK from user OR the alert is closed by another alert. here is what happens in the solution
- parent loads the frame
- parent calls alert()
- alert() is closed by child pdf 
- calculate how long it took the alert to be closed ( if longer than 500ms, go to next char if not go to step 0 )
you can implement timeout stuff with app.setTimeOut