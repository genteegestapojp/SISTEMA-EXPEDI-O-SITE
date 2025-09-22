import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const jwtSecret = process.env.JWT_SECRET;

if (!supabaseUrl || !supabaseServiceKey || !jwtSecret) {
    throw new Error('Variáveis de ambiente não configuradas');
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

export default async function handler(req, res) {
    // CORS
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Método não permitido' });
    }

    const { action, user, password, filial, token } = req.body;

    try {
        if (action === 'login') {
            // Processo de login
            if (!user || !password) {
                return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
            }

            if (!['filiais', 'acessos'].includes('acessos') && !filial) {
                return res.status(400).json({ error: 'Filial é obrigatória' });
            }

            // Verificar credenciais
            const { data: userData } = await supabase
                .from('acessos')
                .select('nome, tipo_acesso')
                .eq('nome', user)
                .eq('senha', password)
                .single();

            if (!userData) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }

            if (userData.tipo_acesso !== 'ALL' && userData.tipo_acesso !== filial) {
                return res.status(403).json({ error: 'Acesso negado a esta filial' });
            }

            // Gerar token JWT
            const authToken = jwt.sign(
                { 
                    userId: userData.nome,
                    filial: filial || 'ALL',
                    tipoAcesso: userData.tipo_acesso,
                    iat: Math.floor(Date.now() / 1000),
                    exp: Math.floor(Date.now() / 1000) + (8 * 60 * 60) // 8 horas
                },
                jwtSecret
            );

            return res.json({
                success: true,
                token: authToken,
                user: {
                    nome: userData.nome,
                    tipo_acesso: userData.tipo_acesso
                },
                expiresIn: 8 * 60 * 60 * 1000 // 8 horas em milissegundos
            });

        } else if (action === 'validate') {
            // Validar token
            if (!token) {
                return res.status(400).json({ error: 'Token é obrigatório' });
            }

            try {
                const decoded = jwt.verify(token, jwtSecret);
                
                // Verificar se o usuário ainda existe
                const { data: userData } = await supabase
                    .from('acessos')
                    .select('nome, tipo_acesso')
                    .eq('nome', decoded.userId)
                    .single();

                if (!userData) {
                    return res.status(401).json({ error: 'Usuário não encontrado' });
                }

                return res.json({
                    valid: true,
                    user: {
                        nome: userData.nome,
                        tipo_acesso: userData.tipo_acesso
                    },
                    filial: decoded.filial,
                    exp: decoded.exp
                });

            } catch (jwtError) {
                return res.status(401).json({ error: 'Token inválido', valid: false });
            }

        } else if (action === 'logout') {
            // Por enquanto, apenas retorna sucesso
            // Em implementação completa, você adicionaria o token a uma blacklist
            return res.json({ success: true, message: 'Logout realizado' });

        } else {
            return res.status(400).json({ error: 'Ação não reconhecida' });
        }

    } catch (error) {
        console.error('Auth error:', error);
        return res.status(500).json({ error: 'Erro interno do servidor' });
    }
}
