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