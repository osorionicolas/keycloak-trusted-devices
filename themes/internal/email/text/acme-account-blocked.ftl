<#ftl output_format="plainText">
<#import "template.ftl" as layout>
<@layout.emailLayout>
${msg("acmeAccountBlockedBody",user.username)}
</@layout.emailLayout>
