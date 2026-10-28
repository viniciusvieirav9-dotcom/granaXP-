# GranaXP

Organizador financeiro gratuito e gamificado. Contas reais (nome de usuário e senha), dados em banco SQLite e painel administrativo protegido no servidor.

## Tecnologias
Node.js 20 ou 22, Express, SQLite (better-sqlite3), bcryptjs (senhas com hash), frontend em HTML/CSS/JS puro (pasta `public`).

## Rodar no seu computador
1. Instale o Node.js 20 ou 22 (versão LTS).
2. Na pasta do projeto: `npm install`
3. Defina a senha administrativa inicial e inicie:
   - Mac/Linux: `ADMIN_PASSWORD=31181022 npm start`
   - Windows (PowerShell): `$env:ADMIN_PASSWORD="31181022"; npm start`
4. Abra http://localhost:3000

## Variáveis de ambiente
| Variável | Para que serve |
|---|---|
| `ADMIN_PASSWORD` | Senha administrativa inicial (mínimo 6 caracteres). Só é lida na primeira vez. |
| `DB_PATH` | Caminho do arquivo do banco. Aponte para um disco persistente. Padrão: `./data/granaxp.db` |
| `NODE_ENV=production` | Ativa cookies `secure` (exige HTTPS). Use ao publicar. |
| `PORT` | Porta do servidor (a hospedagem costuma definir). |
| `RESET_ADMIN=1` | Se esquecer a senha do admin: inicie uma vez com isto e um novo `ADMIN_PASSWORD`, depois remova. |

## Como usar
- **Criar conta:** botão "Começar gratuitamente" na página inicial. O nome de usuário é único; senhas iguais entre pessoas diferentes são permitidas.
- **Admin:** clique na engrenagem discreta no rodapé, digite a senha e entre no painel. Lá você vê números agregados, publica avisos, muda a cor do site e **altera a senha do painel**. Depois da troca, o `ADMIN_PASSWORD` do ambiente deixa de valer.
- Antes de publicar, troque a senha inicial por uma forte e exclusiva.

## Publicar
Precisa de uma hospedagem que rode Node e tenha **disco persistente** para o arquivo do banco (Render, Railway, Fly.io e similares). Sem disco persistente, as contas somem a cada reinício. Confirme esse ponto no plano gratuito escolhido. Hospedagem só de arquivos estáticos (Netlify, GitHub Pages) NÃO serve para esta versão.
Comando de build: `npm install` · Comando de início: `npm start`.

## Checklist de testes (faça antes de divulgar)
1. Criar conta; tentar o mesmo nome de usuário de novo (deve recusar).
2. Duas contas com a mesma senha e nomes diferentes (deve permitir).
3. Entrar com senha errada e certa; errar 6 vezes (deve bloquear por 15 minutos).
4. Sair e entrar de novo: lançamentos, metas e XP continuam.
5. Entrar com duas contas e conferir que um não vê os dados do outro.
6. Reiniciar o servidor e conferir se os dados permanecem.
7. Admin: senha errada, senha certa, trocar a senha e entrar com a nova.
8. Abrir `/api/admin/stats` sem entrar como admin (deve responder 401).
9. Excluir uma conta pelo Perfil e tentar entrar de novo.
10. Testar no celular.

## Limitações conhecidas
- O XP é calculado no navegador; o servidor só limita saltos exagerados (+300 por salvamento). Um usuário técnico ainda pode inflar o próprio XP.
- Sem e-mail, não há recuperação de senha de usuário.
- O limite de tentativas fica na memória e zera ao reiniciar o servidor.
- Falta: gerenciar desafios e conquistas pelo admin, editar lançamentos, cartões compartilháveis e troca de senha do usuário.
