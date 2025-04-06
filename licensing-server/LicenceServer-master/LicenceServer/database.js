import { createClient } from '@supabase/supabase-js';
import 'dotenv/config';

// Initialize Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

export async function storeActivation(licenseId, metadataKey, metadataValue) {
    try {
        const { data, error } = await supabase
            .from('activations')
            .insert([{ license_id: licenseId, metadata_key: metadataKey, metadata_value: metadataValue }]);

        if (error) {
            console.error(`[ERROR] Supabase Insert Failed: ${error.message}`);
            return false;
        }

        console.log(`[INFO] Stored Activation: ${licenseId} -> ${metadataKey}: ${metadataValue}`);
        return true;
    } catch (err) {
        console.error(`[ERROR] Supabase Storage Error: ${err.message}`);
        return false;
    }
}
