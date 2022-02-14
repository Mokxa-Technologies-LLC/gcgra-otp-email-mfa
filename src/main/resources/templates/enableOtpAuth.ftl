<style>
    body {
        margin-top: 0 !important;
    }
    div#main-body-header {
        display: block;
        background: #464646;
        font-size: 18px;
        color: white;
        padding: 8px;
        margin: 0;
    }
    div#main-body-content{
        margin: 16px 8px 0;
    }
</style>
    
<div id="main-body-header">
        @@otpEmail.enable@@
    </div>
    <div id="main-body-content">
        <#if updated! == "true">
            <p>@@otpEmail.activated@@</p>
        <#else>
            <#if error??>
                <div class="form-errors">
                    ${error!}
                </div>
            </#if>
            <form id="enableOtpAuth" action="?a=eotps" class="form" method="POST">
                <fieldset>
                    <div class="form-row">
                        Please check your email for pin.
                        </span>
                    </div>
                    <div class="form-row">
                        <label for="pin">@@otpEmail.pin@@ *</label>
                        <span class="form-input"><input id="pin" name="pin" type="text" value=""/></span>
                    </div>
                </fieldset>
                <div class="form-buttons">
                    <input class="form-button btn button" type="submit" value="Submit" />
                </div>
            </form>
        </#if>
    </div>