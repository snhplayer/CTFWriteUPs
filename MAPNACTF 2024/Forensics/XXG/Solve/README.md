Looking inside this file initially is a PNG, but looking through the strings we can see a .goutputstream, gimp-image-metadata among other things.

Searching leads to some results but one of particular interest(https://www.gimp-forum.net/Thread-Data-gimp-backups-goutputstream-XXXXXX-Files), I see a reply mentioning .xcf files, and have a look at where gimp-image-metadata is to start looking at the data.

```
Gi?? ??? v014ÈúBBõ????-image-grid¬(style solid)
(fgcolor (color-rgba 0 0 0 1))
(bgcolor (color-rgba 1 1 1 1))
(xspacing 10)
(yspacing 10)
(spacing-unit inches)
(xoffset 0)
(yoffset 0)
(offset-unit inches)
gamma0.45455000000000001gimp-image-metadataç<?xml version='1.0' encoding='UTF-8'?>
<metadata>
  <tag name="Exif.Image.BitsPerSample">16 16 16</tag>
  <tag name="Exif.Image.ImageLength">12</tag>
  <tag name="Exif.Image.ImageWidth">200</tag>
  <tag name="Exif.Image.Orientation">1</tag>
  <tag name="Exif.Image.ResolutionUnit">2</tag>
  <tag name="Exif.Image.XResolution">300/1</tag>
  <tag name="Exif.Image.YResolution">300/1</tag>
  <tag name="Exif.Photo.ColorSpace">1</tag>
  <tag name="Xmp.tiff.Orientation">1</tag>
</metadata>
lÈ	????.???ÿ!?	"
 
%$ÿÿÿÿ#ÿÿÿÿuÈ¡amÈÑMáÿçãÏÿÿì¿ÿÿ]¦ÿÿã VFÂãäÿÿKÿþ]¦ÿê³EÖSS¯ÕS[V÷ãSS¯ðRPDÔÿÞOMÿã=uÿÿA¿ÿôUTÿÿã_ÿî=ã<OÿÿKÿÿôUTÿüZßã_ÿùðóÿ¬ã_ÿþÿ×=ÿqÿãlCþÿS}¿ÿ¢ Wéÿã_ÿÿ=ãqZªÿKÿÿ¢ WéÿÿIðã_ÿü¹ã_ÿý¸VôÿÅa¦?ÿãkÁáo¿ÿLðªÿã_ÿÏWãlæ%îKÿÿLðªÿvuÿã WWÎÿÿäFüã WWÎÿ 5üÿ×	¿ÿãkÙhÉ¿åOJ:ÿã VhéãkÿbNÿåOJ:ÿÿKöã_ÿúñIàÿã_ÿýýlÿë¯má>ÿãkÿGNÿ¿²ÿÿ]×ã_ÿîãkÿû+*ÿ²ÿÿ]×ÿWçã_ÿùøRÒÿÿã_ÿûþÿÿ¦ÿë®ÿáÿãkÿ~ÿ¿Dûÿÿ¼zã_ÿîãkÿÿ¾ÿDûÿÿ¼zÿeÎã_ÿù&KKã_ÿûIUZóÿüèSk^!ÿýÙVðQÿÿýkÿùBÿÿçãÏÿÿì¿ÿÿ]¦ÿÿã VFÂãäÿÿKÿþ]¦ÿê³E{SS¯ÕS[V÷ãSS¯ðRPDÔÿÞOMÿã=uÿÿA¿ÿôUTÿÿã_ÿî=ã<OÿÿKÿÿôUTÿüZßã_ÿùðóÿ¬ã_ÿþÿ×=ÿqÿãlCþÿS}¿ÿ¢ Wéÿã_ÿÿ=ãqZªÿKÿÿ¢ WéÿÿIðã_ÿü¹ã_ÿý¸VôÿÅa¦?ÿãkÁáo¿ÿLðªÿã_ÿÏWãlæ%îKÿÿLðªÿvuÿã WWÎÿÿäFüã WWÎÿ 5üÿ×	¿ÿãkÙhÉ¿åOJ:ÿã VhéãkÿbNÿåOJ:ÿÿKöã_ÿúñIàÿã_ÿýýlÿë¯má>ÿãkÿGNÿ¿²ÿÿ]×ã_ÿîãkÿû+*ÿ²ÿÿ]×ÿWçã_ÿùøRÒÿÿã_ÿûþÿÿ¦ÿë®ÿáÿãkÿ~ÿ¿Dûÿÿ¼zã_ÿîãkÿÿ¾ÿDûÿÿ¼zÿeÎã_ÿù&KKã_ÿûIUZóÿüèSk^!ÿýÙVðQÿÿýkÿùBÿÿÿ÷ÿðã XNÿãSS¯ðRPDÔÿ÷saÊÑ"Ûÿã_ÿûÇP[Pòÿöò OOáGäÿëBÿþÆÿøã_ÿÿ?ïã_ÿþÿöþEÿ÷_hÛÿã_ÿûñúÿ¢ÿþárÿû½gÿqµÿÿóÿøã_ÿüCøã_ÿý¸VôÿöuÿÿoÛÿã_ÿýþgÁÿþÐÿôAÀ>ÿÊN]ÿÿ×ùÿðã W.ÿã WWÎÿ 5üÿþûGÿûoÛÿã_ÿü>VùÿôÎE_jñÿº	·ÿ¥ÿýØDþÿøã_ÿþYÏã_ÿýýlÿþûGÿûoÛÿã_ÿþ¦ÿò®|ÿÿ4ÿÿùPÂÿÿøã_ÿÿjÀã_ÿûþÿÿ¦ÿþûGÿûoÛÿã_ÿûýÿÿºxÿû¿{ÿÿ?ÿúõ@ÿAÚÿøã WPfýã_ÿûIUZóÿþûGÿóoÛÿãOO­S\Uéÿò·X]Yìÿÿ?ÿÿ¥Z[Bÿÿýkÿù
ÿÿýkÿùÿÿýkÿùMÿÿÿ÷ÿðã XNÿãSS¯ðRPDÔÿ÷saÊÑ"Ûÿã_ÿûÇP[Pòÿöò OOáGäÿëBÿþÆÿøã_ÿÿ?ïã_ÿþÿöþEÿ÷_hÛÿã_ÿûñúÿ¢ÿþárÿû½gÿqµÿÿóÿøã_ÿüCøã_ÿý¸VôÿöuÿÿoÛÿã_ÿýþgÁÿþÐÿôAÀ>ÿÊN]ÿÿ×ùÿðã W.ÿã WWÎÿ 5üÿþûGÿûoÛÿã_ÿü>VùÿôÎE_jñÿº	·ÿ¥ÿýØDþÿøã_ÿþYÏã_ÿýýlÿþûGÿûoÛÿã_ÿþ¦ÿò®|ÿÿ4ÿÿùPÂÿÿøã_ÿÿjÀã_ÿûþÿÿ¦ÿþûGÿûoÛÿã_ÿûýÿÿºxÿû¿{ÿÿ?ÿúõ@ÿAÚÿøã WPfýã_ÿûIUZóÿþûGÿóoÛÿãOO­S\Uéÿò·X]Yìÿÿ?ÿÿ¥Z[Bÿÿýkÿù
ÿÿýkÿùÿÿýkÿùMÿÿOñDXÇP[PòãÏÿÿì¿	ÿýä
ûÿûãSS¯ÿ÷ãäÿÿKÿÑÿçÇP[PòxWGÿÿ¯ñúÿ¢ã=uÿÿA¿	ÿýfBûÿþã_ÿúã<OÿÿKÿãñúÿ¢þÿÚÿÿDüÿÿþgÁãlCþÿS}¿ÊN]ÿöÃQûÇqT§ã_ÿØãqZªÿKÿÇýeVfÿÿþgÁÿÿÿºÿÿ>VùãkÁáo¿¥ÿòýSøOûÇCþÿã WWÎÿõãlæ%îKÿÇ®ÿö>Vùÿ¸pÿRåÿò¦ãkÙhÉ¿ùPÂÿõ±ÿOûÇ}ÿÿã_ÿõãkÿbNÿÇ´ÿæ¦ÿeýßVÿÿýÿÿºxãkÿGNÿ¿ÿÿõ@ÿõTOOTÇÿÿã_ÿÖãkÿû+*ÿÇ«ÿÿýÿÿºxÿâÿu»ÿÿS\Uéãkÿ~ÿ¿¥Z[ÿõOûÇÿÿãOO­ÿëãkÿÿ¾ÿÇübU[S\Uéÿ3öSÿÿýkÿùÿÿýkÿùSÿÿOñDXÇP[PòãÏÿÿì¿	ÿýä
ûÿûãSS¯ÿ÷ãäÿÿKÿÑÿçÇP[PòxWGÿÿ¯ñúÿ¢ã=uÿÿA¿	ÿýfBûÿþã_ÿúã<OÿÿKÿãñúÿ¢þÿÚÿÿDüÿÿþgÁãlCþÿS}¿ÊN]ÿöÃQûÇqT§ã_ÿØãqZªÿKÿÇýeVfÿÿþgÁÿÿÿºÿÿ>VùãkÁáo¿¥ÿòýSøOûÇCþÿã WWÎÿõãlæ%îKÿÇ®ÿö>Vùÿ¸pÿRåÿò¦ãkÙhÉ¿ùPÂÿõ±ÿOûÇ}ÿÿã_ÿõãkÿbNÿÇ´ÿæ¦ÿeýßVÿÿýÿÿºxãkÿGNÿ¿ÿÿõ@ÿõTOOTÇÿÿã_ÿÖãkÿû+*ÿÇ«ÿÿýÿÿºxÿâÿu»ÿÿS\Uéãkÿ~ÿ¿¥Z[ÿõOûÇÿÿãOO­ÿëãkÿÿ¾ÿÇübU[S\Uéÿ3öSÿÿýkÿùÿÿýkÿùSÿÿûÌÄ^cÿâkÐiÿDöÿÿÜuÿRèÿÿþèÿ®-èÿÿöªÿáÿûûêÿPóÿûÄaÿGûÿþÿÿûÌÄ^cÿâkÐiÿDöÿÿÜuÿRèÿÿþèÿ®-èÿÿöªÿáÿûûêÿPóÿûÄaÿGûÿþÿd2
```
We can see the start of this data having some question marks. I can see ????-image-grid, which I assume ???? to be gimp.

Looking further into the .XCF format(https://developer.gimp.org/core/standards/xcf/#header) we can see the header should be gimp xcf.

The full data is then:

```
gimp xcf v014ÈúBBõgimp-image-grid¬(style solid)
(fgcolor (color-rgba 0 0 0 1))
(bgcolor (color-rgba 1 1 1 1))
(xspacing 10)
(yspacing 10)
(spacing-unit inches)
(xoffset 0)
(yoffset 0)
(offset-unit inches)
gamma0.45455000000000001gimp-image-metadataç<?xml version='1.0' encoding='UTF-8'?>
<metadata>
  <tag name="Exif.Image.BitsPerSample">16 16 16</tag>
  <tag name="Exif.Image.ImageLength">12</tag>
  <tag name="Exif.Image.ImageWidth">200</tag>
  <tag name="Exif.Image.Orientation">1</tag>
  <tag name="Exif.Image.ResolutionUnit">2</tag>
  <tag name="Exif.Image.XResolution">300/1</tag>
  <tag name="Exif.Image.YResolution">300/1</tag>
  <tag name="Exif.Photo.ColorSpace">1</tag>
  <tag name="Xmp.tiff.Orientation">1</tag>
</metadata>
lÈ	????.???ÿ!?	"
 
%$ÿÿÿÿ#ÿÿÿÿuÈ¡amÈÑMáÿçãÏÿÿì¿ÿÿ]¦ÿÿã VFÂãäÿÿKÿþ]¦ÿê³EÖSS¯ÕS[V÷ãSS¯ðRPDÔÿÞOMÿã=uÿÿA¿ÿôUTÿÿã_ÿî=ã<OÿÿKÿÿôUTÿüZßã_ÿùðóÿ¬ã_ÿþÿ×=ÿqÿãlCþÿS}¿ÿ¢ Wéÿã_ÿÿ=ãqZªÿKÿÿ¢ WéÿÿIðã_ÿü¹ã_ÿý¸VôÿÅa¦?ÿãkÁáo¿ÿLðªÿã_ÿÏWãlæ%îKÿÿLðªÿvuÿã WWÎÿÿäFüã WWÎÿ 5üÿ×	¿ÿãkÙhÉ¿åOJ:ÿã VhéãkÿbNÿåOJ:ÿÿKöã_ÿúñIàÿã_ÿýýlÿë¯má>ÿãkÿGNÿ¿²ÿÿ]×ã_ÿîãkÿû+*ÿ²ÿÿ]×ÿWçã_ÿùøRÒÿÿã_ÿûþÿÿ¦ÿë®ÿáÿãkÿ~ÿ¿Dûÿÿ¼zã_ÿîãkÿÿ¾ÿDûÿÿ¼zÿeÎã_ÿù&KKã_ÿûIUZóÿüèSk^!ÿýÙVðQÿÿýkÿùBÿÿçãÏÿÿì¿ÿÿ]¦ÿÿã VFÂãäÿÿKÿþ]¦ÿê³E{SS¯ÕS[V÷ãSS¯ðRPDÔÿÞOMÿã=uÿÿA¿ÿôUTÿÿã_ÿî=ã<OÿÿKÿÿôUTÿüZßã_ÿùðóÿ¬ã_ÿþÿ×=ÿqÿãlCþÿS}¿ÿ¢ Wéÿã_ÿÿ=ãqZªÿKÿÿ¢ WéÿÿIðã_ÿü¹ã_ÿý¸VôÿÅa¦?ÿãkÁáo¿ÿLðªÿã_ÿÏWãlæ%îKÿÿLðªÿvuÿã WWÎÿÿäFüã WWÎÿ 5üÿ×	¿ÿãkÙhÉ¿åOJ:ÿã VhéãkÿbNÿåOJ:ÿÿKöã_ÿúñIàÿã_ÿýýlÿë¯má>ÿãkÿGNÿ¿²ÿÿ]×ã_ÿîãkÿû+*ÿ²ÿÿ]×ÿWçã_ÿùøRÒÿÿã_ÿûþÿÿ¦ÿë®ÿáÿãkÿ~ÿ¿Dûÿÿ¼zã_ÿîãkÿÿ¾ÿDûÿÿ¼zÿeÎã_ÿù&KKã_ÿûIUZóÿüèSk^!ÿýÙVðQÿÿýkÿùBÿÿÿ÷ÿðã XNÿãSS¯ðRPDÔÿ÷saÊÑ"Ûÿã_ÿûÇP[Pòÿöò OOáGäÿëBÿþÆÿøã_ÿÿ?ïã_ÿþÿöþEÿ÷_hÛÿã_ÿûñúÿ¢ÿþárÿû½gÿqµÿÿóÿøã_ÿüCøã_ÿý¸VôÿöuÿÿoÛÿã_ÿýþgÁÿþÐÿôAÀ>ÿÊN]ÿÿ×ùÿðã W.ÿã WWÎÿ 5üÿþûGÿûoÛÿã_ÿü>VùÿôÎE_jñÿº	·ÿ¥ÿýØDþÿøã_ÿþYÏã_ÿýýlÿþûGÿûoÛÿã_ÿþ¦ÿò®|ÿÿ4ÿÿùPÂÿÿøã_ÿÿjÀã_ÿûþÿÿ¦ÿþûGÿûoÛÿã_ÿûýÿÿºxÿû¿{ÿÿ?ÿúõ@ÿAÚÿøã WPfýã_ÿûIUZóÿþûGÿóoÛÿãOO­S\Uéÿò·X]Yìÿÿ?ÿÿ¥Z[Bÿÿýkÿù
ÿÿýkÿùÿÿýkÿùMÿÿÿ÷ÿðã XNÿãSS¯ðRPDÔÿ÷saÊÑ"Ûÿã_ÿûÇP[Pòÿöò OOáGäÿëBÿþÆÿøã_ÿÿ?ïã_ÿþÿöþEÿ÷_hÛÿã_ÿûñúÿ¢ÿþárÿû½gÿqµÿÿóÿøã_ÿüCøã_ÿý¸VôÿöuÿÿoÛÿã_ÿýþgÁÿþÐÿôAÀ>ÿÊN]ÿÿ×ùÿðã W.ÿã WWÎÿ 5üÿþûGÿûoÛÿã_ÿü>VùÿôÎE_jñÿº	·ÿ¥ÿýØDþÿøã_ÿþYÏã_ÿýýlÿþûGÿûoÛÿã_ÿþ¦ÿò®|ÿÿ4ÿÿùPÂÿÿøã_ÿÿjÀã_ÿûþÿÿ¦ÿþûGÿûoÛÿã_ÿûýÿÿºxÿû¿{ÿÿ?ÿúõ@ÿAÚÿøã WPfýã_ÿûIUZóÿþûGÿóoÛÿãOO­S\Uéÿò·X]Yìÿÿ?ÿÿ¥Z[Bÿÿýkÿù
ÿÿýkÿùÿÿýkÿùMÿÿOñDXÇP[PòãÏÿÿì¿	ÿýä
ûÿûãSS¯ÿ÷ãäÿÿKÿÑÿçÇP[PòxWGÿÿ¯ñúÿ¢ã=uÿÿA¿	ÿýfBûÿþã_ÿúã<OÿÿKÿãñúÿ¢þÿÚÿÿDüÿÿþgÁãlCþÿS}¿ÊN]ÿöÃQûÇqT§ã_ÿØãqZªÿKÿÇýeVfÿÿþgÁÿÿÿºÿÿ>VùãkÁáo¿¥ÿòýSøOûÇCþÿã WWÎÿõãlæ%îKÿÇ®ÿö>Vùÿ¸pÿRåÿò¦ãkÙhÉ¿ùPÂÿõ±ÿOûÇ}ÿÿã_ÿõãkÿbNÿÇ´ÿæ¦ÿeýßVÿÿýÿÿºxãkÿGNÿ¿ÿÿõ@ÿõTOOTÇÿÿã_ÿÖãkÿû+*ÿÇ«ÿÿýÿÿºxÿâÿu»ÿÿS\Uéãkÿ~ÿ¿¥Z[ÿõOûÇÿÿãOO­ÿëãkÿÿ¾ÿÇübU[S\Uéÿ3öSÿÿýkÿùÿÿýkÿùSÿÿOñDXÇP[PòãÏÿÿì¿	ÿýä
ûÿûãSS¯ÿ÷ãäÿÿKÿÑÿçÇP[PòxWGÿÿ¯ñúÿ¢ã=uÿÿA¿	ÿýfBûÿþã_ÿúã<OÿÿKÿãñúÿ¢þÿÚÿÿDüÿÿþgÁãlCþÿS}¿ÊN]ÿöÃQûÇqT§ã_ÿØãqZªÿKÿÇýeVfÿÿþgÁÿÿÿºÿÿ>VùãkÁáo¿¥ÿòýSøOûÇCþÿã WWÎÿõãlæ%îKÿÇ®ÿö>Vùÿ¸pÿRåÿò¦ãkÙhÉ¿ùPÂÿõ±ÿOûÇ}ÿÿã_ÿõãkÿbNÿÇ´ÿæ¦ÿeýßVÿÿýÿÿºxãkÿGNÿ¿ÿÿõ@ÿõTOOTÇÿÿã_ÿÖãkÿû+*ÿÇ«ÿÿýÿÿºxÿâÿu»ÿÿS\Uéãkÿ~ÿ¿¥Z[ÿõOûÇÿÿãOO­ÿëãkÿÿ¾ÿÇübU[S\Uéÿ3öSÿÿýkÿùÿÿýkÿùSÿÿûÌÄ^cÿâkÐiÿDöÿÿÜuÿRèÿÿþèÿ®-èÿÿöªÿáÿûûêÿPóÿûÄaÿGûÿþÿÿûÌÄ^cÿâkÐiÿDöÿÿÜuÿRèÿÿþèÿ®-èÿÿöªÿáÿûûêÿPóÿûÄaÿGûÿþÿd2
```

Upon trying to open this in GIMP we are given an error of XCF error: unsupported XCF file version 14 encountered.

We can change the version to v001 in the file at the top.

And we now encounter that the data is corrupt, hmm…

Looking around at XCF file versions it seems people use v011(https://stackoverflow.com/questions/57847730/how-can-gimp-save-older-version-of-xcf-file-format). So trying v011 ends up giving a result!!

![alt text](https://seall.dev/images/ctfs/mapnactf2024/xxg.png)

There we go!

>Flag: MAPNA{F2FS_&_BFS_f1L3_5Ys73Ms_4rE_Nic3?!}